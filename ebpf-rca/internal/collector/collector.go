package collector

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// taskStat 与 cpu.bpf.c 中的 struct task_stat 二进制布局一致（无填充）。
type taskStat struct {
	RunNs  uint64
	RunqNs uint64
	Ctx    uint64
	Comm   [16]byte
}

// Sample 是单个线程在一个采样窗口内的派生指标。
type Sample struct {
	Pid        uint32  // 内核 pid 字段，实际为线程 id(tid)
	Comm       string  // 线程名
	CPUUtil    float64 // 单核 CPU 占用率（1.0 ≈ 占满一个核）
	CtxPerMin  float64 // 每分钟上下文切换次数
	RunqWaitUs float64 // 平均运行队列等待时间(微秒)
}

// CPUCollector 加载 CPU 场景的 eBPF 程序并按窗口读取聚合数据。
type CPUCollector struct {
	objs  cpuObjects
	links []link.Link
	prev  map[uint32]taskStat
	stale map[uint32]int
}

// NewCPUCollector 加载字节码、挂载 tracepoint。
func NewCPUCollector() (*CPUCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &CPUCollector{
		prev:  make(map[uint32]taskStat),
		stale: make(map[uint32]int),
	}
	if err := loadCpuObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
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
	return c, nil
}

// Close 卸载探针并释放资源。
func (c *CPUCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

// Poll 读取 stats map，计算自上次调用以来的差分指标。
func (c *CPUCollector) Poll(interval time.Duration) ([]Sample, error) {
	raw := make(map[uint32]taskStat)
	var key uint32
	var val taskStat
	it := c.objs.Stats.Iterate()
	for it.Next(&key, &val) {
		raw[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate stats: %w", err)
	}

	oncpu := make(map[uint32]uint64)
	var ts uint64
	it = c.objs.OncpuStart.Iterate()
	for it.Next(&key, &ts) {
		oncpu[key] = ts
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate oncpu_start: %w", err)
	}

	nowNS := monotonicNowNS()
	cur := make(map[uint32]taskStat, len(raw))
	for tid, v := range raw {
		if start, ok := oncpu[tid]; ok && nowNS > start {
			v.RunNs += nowNS - start
		}
		cur[tid] = v
	}

	intervalNs := float64(interval.Nanoseconds())
	intervalMin := interval.Minutes()
	var samples []Sample
	for tid, v := range cur {
		var dRun, dRunq, dCtx uint64
		if p, ok := c.prev[tid]; ok {
			dRun = v.RunNs - p.RunNs
			dRunq = v.RunqNs - p.RunqNs
			dCtx = v.Ctx - p.Ctx
		} else {
			dRun, dRunq, dCtx = v.RunNs, v.RunqNs, v.Ctx
		}
		if shouldDeleteStale(c.stale, tid, dRun == 0 && dCtx == 0) {
			_ = c.objs.Stats.Delete(tid)
			_ = c.objs.OncpuStart.Delete(tid)
			_ = c.objs.WakeupTs.Delete(tid)
			delete(cur, tid)
			continue
		}
		if dRun == 0 && dCtx == 0 {
			continue
		}
		s := Sample{
			Pid:     tid,
			Comm:    commToString(v.Comm),
			CPUUtil: 0,
		}
		if intervalNs > 0 {
			s.CPUUtil = float64(dRun) / intervalNs
		}
		if intervalMin > 0 {
			s.CtxPerMin = float64(dCtx) / intervalMin
		}
		if dCtx > 0 {
			s.RunqWaitUs = float64(dRunq) / float64(dCtx) / 1000.0
		}
		samples = append(samples, s)
	}
	c.prev = cur
	return samples, nil
}

func commToString(b [16]byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
