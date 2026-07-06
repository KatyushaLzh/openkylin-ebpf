package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// memStat 与 mem.bpf.c 中的 struct mem_stat 二进制布局一致。
type memStat struct {
	DirectReclaimCount uint64
	DirectReclaimNs    uint64
	Comm               [16]byte
}

type fault struct{ maj, min uint64 }

// MemProc 是单个进程在窗口内的内存压力贡献。
type MemProc struct {
	Pid                uint32
	Comm               string
	DirectReclaimCount uint64  // 窗口内直接回收次数
	DirectReclaimMs    float64 // 窗口内直接回收耗时(ms)
	MajFlt             uint64  // 窗口内 major fault 增量
	MinFlt             uint64  // 窗口内 minor fault 增量
}

// MemSnapshot 是一个窗口的系统内存状态与 per-process 压力贡献。
type MemSnapshot struct {
	MemAvailablePct float64
	MemTotalKB      uint64
	MemAvailableKB  uint64
	KswapdWakes     uint64 // 窗口内增量
	Procs           []MemProc
}

// MemCollector 加载内存场景的 eBPF 程序并汇总系统内存压力。
type MemCollector struct {
	objs       memObjects
	links      []link.Link
	prev       map[uint32]memStat
	prevFault  map[uint32]fault
	prevKswapd uint64
}

// NewMemCollector 加载字节码、挂载 vmscan tracepoint。
func NewMemCollector() (*MemCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &MemCollector{
		prev:      make(map[uint32]memStat),
		prevFault: make(map[uint32]fault),
	}
	if err := loadMemObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	begin, err := link.Tracepoint("vmscan", "mm_vmscan_direct_reclaim_begin", c.objs.HandleDirectBegin, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach direct_reclaim_begin: %w", err)
	}
	c.links = append(c.links, begin)

	end, err := link.Tracepoint("vmscan", "mm_vmscan_direct_reclaim_end", c.objs.HandleDirectEnd, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach direct_reclaim_end: %w", err)
	}
	c.links = append(c.links, end)

	kw, err := link.Tracepoint("vmscan", "mm_vmscan_kswapd_wake", c.objs.HandleKswapdWake, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach kswapd_wake: %w", err)
	}
	c.links = append(c.links, kw)
	return c, nil
}

// Close 卸载探针并释放资源。
func (c *MemCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

// Poll 汇总一个窗口的系统内存状态与进程压力贡献。
func (c *MemCollector) Poll(interval time.Duration) (MemSnapshot, error) {
	total, avail := readMemInfo()
	snap := MemSnapshot{MemTotalKB: total, MemAvailableKB: avail}
	if total > 0 {
		snap.MemAvailablePct = float64(avail) / float64(total) * 100
	}

	// kswapd 唤醒(全局)增量
	var kw uint64
	if err := c.objs.KswapdWakes.Lookup(uint32(0), &kw); err == nil {
		snap.KswapdWakes = kw - c.prevKswapd
		c.prevKswapd = kw
	}

	cur := make(map[uint32]memStat)
	var key uint32
	var val memStat
	it := c.objs.MemStats.Iterate()
	for it.Next(&key, &val) {
		cur[key] = val
	}
	if err := it.Err(); err != nil {
		return snap, fmt.Errorf("iterate mem_stats: %w", err)
	}

	for pid, v := range cur {
		p := c.prev[pid]
		dCount := v.DirectReclaimCount - p.DirectReclaimCount
		dNs := v.DirectReclaimNs - p.DirectReclaimNs
		maj, min := readProcFaults(pid)
		pf := c.prevFault[pid]
		proc := MemProc{
			Pid:                pid,
			Comm:               commToString(v.Comm),
			DirectReclaimCount: dCount,
			DirectReclaimMs:    float64(dNs) / 1e6,
			MajFlt:             saturatingSub(maj, pf.maj),
			MinFlt:             saturatingSub(min, pf.min),
		}
		c.prevFault[pid] = fault{maj: maj, min: min}
		if proc.DirectReclaimCount > 0 || proc.MajFlt > 0 {
			snap.Procs = append(snap.Procs, proc)
		}
	}
	c.prev = cur
	return snap, nil
}

func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// readMemInfo 返回 /proc/meminfo 的 MemTotal、MemAvailable（kB）。
func readMemInfo() (total, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return total, avail
}

// readProcFaults 读取 /proc/<pid>/stat 的 minflt(字段10)、majflt(字段12)。
func readProcFaults(pid uint32) (maj, min uint64) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0
	}
	s := string(b)
	// comm 可能含空格/括号，跳到最后一个 ')' 之后再按空格切分。
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+2 >= len(s) {
		return 0, 0
	}
	fields := strings.Fields(s[rp+2:]) // fields[0]=state(字段3)
	// 字段10(minflt) -> idx 7；字段12(majflt) -> idx 9
	if len(fields) > 9 {
		min, _ = strconv.ParseUint(fields[7], 10, 64)
		maj, _ = strconv.ParseUint(fields[9], 10, 64)
	}
	return maj, min
}
