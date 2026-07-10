package collector

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/ksym"
)

const (
	maxStackDepth = 32
	lockHistSlots = 48
	futexOpNone   = ^uint32(0)
)

type lockKey struct {
	Tgid        uint32
	Tid         uint32
	LockAddress uint64
	StackID     int32
	FutexOp     uint32
}

type lockStat struct {
	OffcpuNs    uint64
	OffcpuCount uint64
	LastWaker   uint32
	Pad         uint32
	Comm        [16]byte
	Slots       [lockHistSlots]uint64
}

type LockWaiter struct {
	Tid         uint32  `json:"tid" yaml:"tid"`
	Comm        string  `json:"comm" yaml:"comm"`
	TotalWaitMs float64 `json:"total_wait_ms" yaml:"total_wait_ms"`
	WaitCount   uint64  `json:"wait_count" yaml:"wait_count"`
	MaxWaitMs   float64 `json:"max_wait_ms" yaml:"max_wait_ms"`
}

// LockSample is grouped by a real futex instance, or by blocking stack when
// the kernel wait has no user-space address.  Pid is a TGID; Tid is the top
// waiter and never masquerades as a process ID.
type LockSample struct {
	Window      ObservationWindow
	Pid         uint32
	Tid         uint32
	Comm        string
	LockAddress uint64
	FutexOp     uint32
	Futex       bool
	Targeted    bool
	OffcpuRatio float64
	TotalWaitMs float64
	BlockCount  uint64
	WaiterCount int
	P99OffcpuMs float64
	MaxOffcpuMs float64
	LastWaker   uint32
	StackID     int32
	TopWaiters  []LockWaiter
}

type LockCollector struct {
	objs       lockObjects
	links      []link.Link
	ksyms      *ksym.Table
	prev       map[lockKey]lockStat
	stale      map[lockKey]int
	lastPollNS uint64
	target     *targetTracker
	selfTGID   uint32
}

func NewLockCollector(targetPID uint32) (*LockCollector, error) {
	target := newTargetTracker(targetPID)
	if err := target.initialize(); err != nil {
		return nil, err
	}
	symbols, err := ksym.Load()
	if err != nil {
		return nil, fmt.Errorf("load /proc/kallsyms required for lock classification: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &LockCollector{
		prev:     make(map[lockKey]lockStat),
		stale:    make(map[lockKey]int),
		target:   target,
		selfTGID: uint32(os.Getpid()),
		ksyms:    symbols,
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
	programs := []struct {
		name string
		prog *ebpf.Program
	}{
		// Attach the cleanup side first. An unmatched early fexit is harmless;
		// attaching fentry first could leave a stale futex_active entry when a
		// call returns in the attachment gap.
		{"fexit/do_futex", c.objs.HandleFutexExit},
		{"fentry/do_futex", c.objs.HandleFutexEnter},
		// Wakeup consumers precede the sched_switch producer so every recorded
		// off-CPU interval can capture its first post-attach wakeup.
		{"tp_btf/sched_wakeup", c.objs.HandleWakeup},
		{"tp_btf/sched_wakeup_new", c.objs.HandleWakeupNew},
		{"tp_btf/sched_switch", c.objs.HandleSwitch},
	}
	for _, item := range programs {
		l, err := link.AttachTracing(link.TracingOptions{Program: item.prog})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s (kernel 6.6+BTF/fentry required): %w", item.name, err)
		}
		c.links = append(c.links, l)
	}
	return c, nil
}

func (c *LockCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

type lockGroupKey struct {
	tgid        uint32
	address     uint64
	kernelStack int32
}

type lockWaiterAggregate struct {
	tid     uint32
	comm    string
	totalNS uint64
	count   uint64
	maxNS   uint64
}

type lockAggregate struct {
	key          lockGroupKey
	totalNS      uint64
	count        uint64
	slots        [lockHistSlots]uint64
	waiters      map[uint32]*lockWaiterAggregate
	stackID      int32
	stackTotalNS uint64
	futexOp      uint32
	lastWaker    uint32
}

func (c *LockCollector) Poll(interval time.Duration) ([]LockSample, error) {
	if err := c.refreshTargetTGIDs(); err != nil {
		return nil, err
	}
	elapsed := c.measuredElapsed(interval)
	window := NewObservationWindow(time.Now(), elapsed)
	if !window.Valid() {
		return nil, fmt.Errorf("invalid lock observation window: %s", elapsed)
	}
	cur := make(map[lockKey]lockStat)
	var key lockKey
	var value lockStat
	it := c.objs.LockStats.Iterate()
	for it.Next(&key, &value) {
		cur[key] = value
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate lock_stats: %w", err)
	}
	if err := drainObservedTGIDs(c.objs.ObservedTgids, c.target); err != nil {
		return nil, err
	}

	groups := make(map[lockGroupKey]*lockAggregate)
	for key, value := range cur {
		// In global mode the observer's own Go runtime parks worker threads in
		// futexes. Reporting those waits would be a deterministic observer-effect
		// false positive, so key the exclusion by TGID rather than mutable comm.
		if !c.target.enabled() && key.Tgid == c.selfTGID {
			_ = c.objs.LockStats.Delete(key)
			_ = c.objs.OffcpuStart.Delete(key.Tid)
			_ = c.objs.FutexActive.Delete(key.Tid)
			delete(cur, key)
			delete(c.stale, key)
			continue
		}
		if c.target.enabled() && !c.target.containsTGID(key.Tgid) {
			_ = c.objs.LockStats.Delete(key)
			_ = c.objs.OffcpuStart.Delete(key.Tid)
			_ = c.objs.FutexActive.Delete(key.Tid)
			delete(cur, key)
			delete(c.stale, key)
			continue
		}
		old := c.prev[key]
		dNS := saturatingSub(value.OffcpuNs, old.OffcpuNs)
		dCount := saturatingSub(value.OffcpuCount, old.OffcpuCount)
		if dNS == 0 && dCount == 0 {
			if !taskExists(taskKey{Tgid: key.Tgid, Tid: key.Tid}) {
				c.stale[key]++
				if c.stale[key] >= staleWindowsBeforeDelete {
					_ = c.objs.LockStats.Delete(key)
					delete(cur, key)
					delete(c.stale, key)
				}
			} else {
				delete(c.stale, key)
			}
			continue
		}
		delete(c.stale, key)

		groupKey := lockGroupKey{tgid: key.Tgid, address: key.LockAddress}
		if key.LockAddress == 0 {
			groupKey.kernelStack = key.StackID
		}
		agg := groups[groupKey]
		if agg == nil {
			agg = &lockAggregate{
				key:     groupKey,
				waiters: make(map[uint32]*lockWaiterAggregate),
				stackID: key.StackID,
				futexOp: key.FutexOp,
			}
			groups[groupKey] = agg
		}
		agg.totalNS += dNS
		agg.count += dCount
		var waiterSlots [lockHistSlots]uint64
		for slot := range value.Slots {
			delta := saturatingSub(value.Slots[slot], old.Slots[slot])
			waiterSlots[slot] = delta
			agg.slots[slot] += delta
		}
		waiter := agg.waiters[key.Tid]
		if waiter == nil {
			waiter = &lockWaiterAggregate{tid: key.Tid, comm: commToString(value.Comm)}
			agg.waiters[key.Tid] = waiter
		}
		waiter.totalNS += dNS
		waiter.count += dCount
		if maximum := maxNSFromLockSlots(waiterSlots); maximum > waiter.maxNS {
			waiter.maxNS = maximum
		}
		if dNS > agg.stackTotalNS {
			agg.stackTotalNS = dNS
			agg.stackID = key.StackID
			agg.futexOp = key.FutexOp
			agg.lastWaker = value.LastWaker
		}
	}
	c.prev = cur

	samples := make([]LockSample, 0, len(groups))
	for _, agg := range groups {
		waiters := make([]LockWaiter, 0, len(agg.waiters))
		for _, waiter := range agg.waiters {
			waiters = append(waiters, LockWaiter{
				Tid:         waiter.tid,
				Comm:        waiter.comm,
				TotalWaitMs: float64(waiter.totalNS) / 1e6,
				WaitCount:   waiter.count,
				MaxWaitMs:   float64(waiter.maxNS) / 1e6,
			})
		}
		sort.Slice(waiters, func(i, j int) bool {
			if waiters[i].TotalWaitMs != waiters[j].TotalWaitMs {
				return waiters[i].TotalWaitMs > waiters[j].TotalWaitMs
			}
			return waiters[i].Tid < waiters[j].Tid
		})
		if len(waiters) > 5 {
			waiters = waiters[:5]
		}
		sample := LockSample{
			Window:      window,
			Pid:         agg.key.tgid,
			LockAddress: agg.key.address,
			FutexOp:     agg.futexOp,
			Futex:       agg.key.address != 0 && agg.futexOp != futexOpNone,
			Targeted:    c.target.enabled(),
			TotalWaitMs: float64(agg.totalNS) / 1e6,
			BlockCount:  agg.count,
			WaiterCount: len(agg.waiters),
			P99OffcpuMs: float64(percentileNSFromLockSlots(agg.slots, 99)) / 1e6,
			MaxOffcpuMs: float64(maxNSFromLockSlots(agg.slots)) / 1e6,
			LastWaker:   agg.lastWaker,
			StackID:     agg.stackID,
			TopWaiters:  waiters,
		}
		if elapsed > 0 {
			sample.OffcpuRatio = float64(agg.totalNS) / float64(elapsed)
		}
		if len(waiters) > 0 {
			sample.Tid = waiters[0].Tid
			sample.Comm = waiters[0].Comm
		}
		samples = append(samples, sample)
	}
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].OffcpuRatio != samples[j].OffcpuRatio {
			return samples[i].OffcpuRatio > samples[j].OffcpuRatio
		}
		if samples[i].Pid != samples[j].Pid {
			return samples[i].Pid < samples[j].Pid
		}
		return samples[i].LockAddress < samples[j].LockAddress
	})
	return samples, nil
}

func (c *LockCollector) measuredElapsed(fallback time.Duration) time.Duration {
	now := monotonicNowNS()
	old := c.lastPollNS
	c.lastPollNS = now
	if old != 0 && now > old {
		return time.Duration(now - old)
	}
	return fallback
}

func maxNSFromLockSlots(slots [lockHistSlots]uint64) uint64 {
	for slot := lockHistSlots - 1; slot >= 0; slot-- {
		if slots[slot] != 0 {
			return lockBucketUpperNS(slot)
		}
	}
	return 0
}

func percentileNSFromLockSlots(slots [lockHistSlots]uint64, percentile uint64) uint64 {
	var total uint64
	for _, count := range slots {
		total += count
	}
	if total == 0 {
		return 0
	}
	target := (total*percentile + 99) / 100
	var seen uint64
	for slot, count := range slots {
		seen += count
		if seen >= target {
			return lockBucketUpperNS(slot)
		}
	}
	return lockBucketUpperNS(lockHistSlots - 1)
}

func lockBucketUpperNS(slot int) uint64 {
	return (uint64(1) << uint(slot+1)) - 1
}

func (c *LockCollector) refreshTargetTGIDs() error {
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

func (c *LockCollector) ResolveStack(id int32, max int) []string {
	if id < 0 {
		return nil
	}
	var frames [maxStackDepth]uint64
	if err := c.objs.Stackmap.Lookup(uint32(id), &frames); err != nil {
		return nil
	}
	var out []string
	for _, address := range frames {
		if address == 0 {
			break
		}
		if c.ksyms != nil {
			out = append(out, c.ksyms.Resolve(address))
		} else {
			out = append(out, fmt.Sprintf("0x%x", address))
		}
		if len(out) >= max {
			break
		}
	}
	return out
}
