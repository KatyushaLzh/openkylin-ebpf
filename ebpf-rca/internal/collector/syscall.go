package collector

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/syscalls"
)

// scKey 与 syscall.bpf.c 中的 struct sc_key 布局一致。
type scKey struct {
	Pid uint32
	Nr  uint32
}

// scStat 与 syscall.bpf.c 中的 struct sc_stat 布局一致。
type scStat struct {
	Count   uint64
	TotalNs uint64
	MaxNs   uint64
	Comm    [16]byte
	Slots   [histNSlots]uint64
}

// SyscallSample 是单个 (进程, syscall) 在窗口内的派生指标。
type SyscallSample struct {
	Pid           uint32
	Comm          string
	Nr            uint32
	Syscall       string
	CallsPerSec   float64
	AvgLatUs      float64
	TotalMsPerSec float64 // 窗口内该 syscall 累计耗时(ms)/秒
	MaxLatUs      float64
}

// SyscallCollector 加载 syscall 热点场景的 eBPF 程序。
type SyscallCollector struct {
	objs      syscallObjects
	links     []link.Link
	prev      map[scKey]scStat
	stale     map[scKey]int
	targetPID uint32
}

// NewSyscallCollector 加载字节码、挂载 raw_syscalls tracepoint。
func NewSyscallCollector(targetPID uint32) (*SyscallCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &SyscallCollector{
		prev:      make(map[scKey]scStat),
		stale:     make(map[scKey]int),
		targetPID: targetPID,
	}
	if err := loadSyscallObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	if err := c.objs.TargetPid.Put(uint32(0), targetPID); err != nil {
		c.Close()
		return nil, fmt.Errorf("set target pid: %w", err)
	}
	en, err := link.Tracepoint("raw_syscalls", "sys_enter", c.objs.HandleEnter, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach sys_enter: %w", err)
	}
	c.links = append(c.links, en)

	ex, err := link.Tracepoint("raw_syscalls", "sys_exit", c.objs.HandleExit, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach sys_exit: %w", err)
	}
	c.links = append(c.links, ex)
	return c, nil
}

// Close 卸载探针并释放资源。
func (c *SyscallCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

// Poll 读取 syscall_stats，计算自上次调用以来的差分。
func (c *SyscallCollector) Poll(interval time.Duration) ([]SyscallSample, error) {
	cur := make(map[scKey]scStat)
	var key scKey
	var val scStat
	it := c.objs.SyscallStats.Iterate()
	for it.Next(&key, &val) {
		cur[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate syscall_stats: %w", err)
	}

	secs := interval.Seconds()
	var samples []SyscallSample
	for k, v := range cur {
		p := c.prev[k]
		dCount := v.Count - p.Count
		dTotal := v.TotalNs - p.TotalNs
		if dCount == 0 && !procExists(k.Pid) {
			c.stale[k]++
			if c.stale[k] >= staleWindowsBeforeDelete {
				_ = c.objs.SyscallStats.Delete(k)
				delete(cur, k)
				continue
			}
		} else {
			delete(c.stale, k)
		}
		if dCount == 0 {
			continue
		}
		comm := commToString(v.Comm)
		if c.targetPID == 0 && comm == "ebpf-rca" {
			continue
		}
		s := SyscallSample{
			Pid:      k.Pid,
			Comm:     comm,
			Nr:       k.Nr,
			Syscall:  syscalls.Name(k.Nr),
			MaxLatUs: float64(maxNSFromSlots(v.Slots, p.Slots)) / 1000.0,
		}
		if secs > 0 {
			s.CallsPerSec = float64(dCount) / secs
			s.TotalMsPerSec = float64(dTotal) / secs / 1e6
		}
		s.AvgLatUs = float64(dTotal) / float64(dCount) / 1000.0
		samples = append(samples, s)
	}
	c.prev = cur
	return samples, nil
}
