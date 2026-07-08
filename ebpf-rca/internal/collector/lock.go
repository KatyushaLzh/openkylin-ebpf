package collector

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/ksym"
)

const maxStackDepth = 32

// lockStat 与 lock.bpf.c 中的 struct lock_stat 二进制布局一致。
type lockStat struct {
	OffcpuNs    uint64
	OffcpuCount uint64
	MaxOffcpuNs uint64
	LastWaker   uint32
	StackID     int32
	Comm        [16]byte
	Slots       [histNSlots]uint64
}

// LockSample 是单个线程在一个窗口内的 off-CPU 阻塞派生指标。
type LockSample struct {
	Pid         uint32
	Comm        string
	OffcpuRatio float64 // 阻塞型 off-CPU 时间占墙钟比例(0..1)
	BlockCount  uint64  // 窗口内阻塞次数
	MaxOffcpuMs float64 // 单次最长阻塞(毫秒,累计最大值)
	LastWaker   uint32  // 最近唤醒者 tid
	StackID     int32   // 阻塞内核栈 id（用于符号化）
}

// LockCollector 加载锁竞争场景的 eBPF 程序并读取 off-CPU 阻塞数据。
type LockCollector struct {
	objs   lockObjects
	links  []link.Link
	ksyms  *ksym.Table
	prev   map[uint32]lockStat
	stale  map[uint32]int
	target *targetTracker
}

// NewLockCollector 加载字节码、挂载 tracepoint、载入内核符号表。
func NewLockCollector(targetPID uint32) (*LockCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &LockCollector{
		prev:   make(map[uint32]lockStat),
		stale:  make(map[uint32]int),
		target: newTargetTracker(targetPID),
	}
	if err := loadLockObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	if err := c.objs.TargetPid.Put(uint32(0), targetPID); err != nil {
		c.Close()
		return nil, fmt.Errorf("set target pid: %w", err)
	}
	if err := c.refreshTargetTGIDs(); err != nil {
		c.Close()
		return nil, err
	}
	sw, err := link.Tracepoint("sched", "sched_switch", c.objs.HandleSwitch, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach sched_switch: %w", err)
	}
	c.links = append(c.links, sw)

	wk, err := link.Tracepoint("sched", "sched_wakeup", c.objs.HandleWakeup, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach sched_wakeup: %w", err)
	}
	c.links = append(c.links, wk)

	// 符号表载入失败不致命：仍可输出地址。
	if t, err := ksym.Load(); err == nil {
		c.ksyms = t
	}
	return c, nil
}

// Close 卸载探针并释放资源。
func (c *LockCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

// Poll 读取 lock_stats，计算自上次调用以来的差分。
func (c *LockCollector) Poll(interval time.Duration) ([]LockSample, error) {
	if err := c.refreshTargetTGIDs(); err != nil {
		return nil, err
	}
	cur := make(map[uint32]lockStat)
	var key uint32
	var val lockStat
	it := c.objs.LockStats.Iterate()
	for it.Next(&key, &val) {
		cur[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate lock_stats: %w", err)
	}

	intervalNs := float64(interval.Nanoseconds())
	var samples []LockSample
	for tid, v := range cur {
		if c.target.enabled() && !c.target.containsTID(tid) {
			_ = c.objs.LockStats.Delete(tid)
			_ = c.objs.OffcpuStart.Delete(tid)
			delete(cur, tid)
			continue
		}
		var dOff, dCount uint64
		if p, ok := c.prev[tid]; ok {
			dOff = v.OffcpuNs - p.OffcpuNs
			dCount = v.OffcpuCount - p.OffcpuCount
		} else {
			dOff, dCount = v.OffcpuNs, v.OffcpuCount
		}
		if shouldDeleteStale(c.stale, tid, dOff == 0 && dCount == 0) {
			_ = c.objs.LockStats.Delete(tid)
			_ = c.objs.OffcpuStart.Delete(tid)
			delete(cur, tid)
			continue
		}
		if dOff == 0 && dCount == 0 {
			continue
		}
		samples = append(samples, LockSample{
			Pid:         tid,
			Comm:        commToString(v.Comm),
			OffcpuRatio: float64(dOff) / intervalNs,
			BlockCount:  dCount,
			MaxOffcpuMs: float64(maxNSFromSlots(v.Slots, c.prev[tid].Slots)) / 1e6,
			LastWaker:   v.LastWaker,
			StackID:     v.StackID,
		})
	}
	c.prev = cur
	return samples, nil
}

func (c *LockCollector) refreshTargetTGIDs() error {
	if !c.target.enabled() {
		return nil
	}
	c.target.refresh()
	desired := make(map[uint32]struct{})
	for _, tgid := range c.target.targetTGIDs() {
		desired[tgid] = struct{}{}
	}
	var key uint32
	var val uint8
	it := c.objs.TargetTgids.Iterate()
	for it.Next(&key, &val) {
		if _, ok := desired[key]; ok {
			continue
		}
		_ = c.objs.TargetTgids.Delete(key)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate target_tgids: %w", err)
	}
	one := uint8(1)
	for tgid := range desired {
		if err := c.objs.TargetTgids.Put(tgid, one); err != nil {
			return fmt.Errorf("update target_tgids: %w", err)
		}
	}
	return nil
}

// ResolveStack 将阻塞栈 id 符号化为最多 max 个栈帧函数名。
func (c *LockCollector) ResolveStack(id int32, max int) []string {
	if id < 0 {
		return nil
	}
	var frames [maxStackDepth]uint64
	if err := c.objs.Stackmap.Lookup(uint32(id), &frames); err != nil {
		return nil
	}
	var out []string
	for _, a := range frames {
		if a == 0 {
			break
		}
		if c.ksyms != nil {
			out = append(out, c.ksyms.Resolve(a))
		} else {
			out = append(out, fmt.Sprintf("0x%x", a))
		}
		if len(out) >= max {
			break
		}
	}
	return out
}
