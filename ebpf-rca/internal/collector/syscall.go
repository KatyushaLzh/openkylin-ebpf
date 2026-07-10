package collector

import (
	"fmt"
	"os"
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
	Window        ObservationWindow
	Pid           uint32
	Comm          string
	Nr            uint32
	Syscall       string
	CallsPerSec   float64
	AvgLatUs      float64
	P99LatUs      float64
	TotalMsPerSec float64 // 窗口内该 syscall 累计耗时(ms)/秒
	MaxLatUs      float64
}

// SyscallCollector 加载 syscall 热点场景的 eBPF 程序。
type SyscallCollector struct {
	objs       syscallObjects
	links      []link.Link
	prev       map[scKey]scStat
	stale      map[scKey]int
	targetPID  uint32
	target     *targetTracker
	lastPollNS uint64
	selfTGID   uint32
}

// NewSyscallCollector 加载字节码并挂载 tp_btf/sys_enter 与 tp_btf/sys_exit。
func NewSyscallCollector(targetPID uint32) (*SyscallCollector, error) {
	target := newTargetTracker(targetPID)
	if err := target.initialize(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &SyscallCollector{
		prev:      make(map[scKey]scStat),
		stale:     make(map[scKey]int),
		targetPID: targetPID,
		target:    target,
		selfTGID:  uint32(os.Getpid()),
	}
	if err := loadSyscallObjects(&c.objs, nil); err != nil {
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
	en, err := link.AttachTracing(link.TracingOptions{Program: c.objs.HandleEnter})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach tp_btf/sys_enter (kernel 6.6+BTF required): %w", err)
	}
	c.links = append(c.links, en)
	// Attach enter first, then seed TIDs that may already be inside a syscall,
	// then attach exit. handle_enter/matched exit both clear stale markers, so
	// only a genuinely unobserved pre-attach enter is suppressed.
	if err := seedStartupTIDs(c.objs.StartupTids); err != nil {
		c.Close()
		return nil, fmt.Errorf("seed pre-attach syscall tids: %w", err)
	}

	ex, err := link.AttachTracing(link.TracingOptions{Program: c.objs.HandleExit})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach tp_btf/sys_exit (kernel 6.6+BTF required): %w", err)
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
	if err := c.refreshTargetTGIDs(); err != nil {
		return nil, err
	}
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
	if err := drainObservedTGIDs(c.objs.ObservedTgids, c.target); err != nil {
		return nil, err
	}

	elapsed := c.measuredElapsed(interval)
	window := NewObservationWindow(time.Now(), elapsed)
	if !window.Valid() {
		return nil, fmt.Errorf("invalid syscall observation window: %s", elapsed)
	}
	secs := elapsed.Seconds()
	var samples []SyscallSample
	for k, v := range cur {
		if c.targetPID == 0 && k.Pid == c.selfTGID {
			_ = c.objs.SyscallStats.Delete(k)
			delete(cur, k)
			delete(c.stale, k)
			continue
		}
		if c.target.enabled() && !c.target.containsTGID(k.Pid) {
			_ = c.objs.SyscallStats.Delete(k)
			delete(cur, k)
			continue
		}
		p := c.prev[k]
		dCount := saturatingSub(v.Count, p.Count)
		dTotal := saturatingSub(v.TotalNs, p.TotalNs)
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
		s := SyscallSample{
			Window:   window,
			Pid:      k.Pid,
			Comm:     comm,
			Nr:       k.Nr,
			Syscall:  syscalls.Name(k.Nr),
			MaxLatUs: float64(maxNSUpperFromSlots(v.Slots, p.Slots)) / 1000.0,
			P99LatUs: float64(percentileNSFromSlots(v.Slots, p.Slots, 99)) / 1000.0,
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

func (c *SyscallCollector) measuredElapsed(fallback time.Duration) time.Duration {
	now := monotonicNowNS()
	old := c.lastPollNS
	c.lastPollNS = now
	if old != 0 && now > old {
		return time.Duration(now - old)
	}
	return fallback
}

func maxNSUpperFromSlots(cur, prev [histNSlots]uint64) uint64 {
	for slot := histNSlots - 1; slot >= 0; slot-- {
		if cur[slot] > prev[slot] {
			return histogramBucketUpperNS(slot)
		}
	}
	return 0
}

func percentileNSFromSlots(cur, prev [histNSlots]uint64, percentile uint64) uint64 {
	var total uint64
	var delta [histNSlots]uint64
	for slot := range cur {
		delta[slot] = saturatingSub(cur[slot], prev[slot])
		total += delta[slot]
	}
	if total == 0 {
		return 0
	}
	target := (total*percentile + 99) / 100
	var seen uint64
	for slot, count := range delta {
		seen += count
		if seen >= target {
			return histogramBucketUpperNS(slot)
		}
	}
	return histogramBucketUpperNS(histNSlots - 1)
}

func histogramBucketUpperNS(slot int) uint64 {
	return (uint64(1) << uint(slot+1)) - 1
}

func (c *SyscallCollector) refreshTargetTGIDs() error {
	if !c.target.enabled() {
		return nil
	}
	c.target.refresh()
	if err := drainObservedTGIDs(c.objs.ObservedTgids, c.target); err != nil {
		return err
	}
	if err := c.objs.TargetPid.Put(uint32(0), c.target.bpfFilterRoot()); err != nil {
		return fmt.Errorf("update target root identity: %w", err)
	}
	return syncTargetTGIDMap(c.objs.TargetTgids, c.target.targetTGIDSeeds())
}
