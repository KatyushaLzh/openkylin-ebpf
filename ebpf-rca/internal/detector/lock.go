package detector

import "github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"

type LockSignal struct {
	Sample collector.LockSample
	Window collector.ObservationWindow
}

type lockIdentity struct {
	tgid        uint32
	address     uint64
	kernelStack int32
}

func identityOfLock(sample collector.LockSample) lockIdentity {
	id := lockIdentity{tgid: sample.Pid, address: sample.LockAddress}
	if sample.LockAddress == 0 {
		id.kernelStack = sample.StackID
	}
	return id
}

type LockDetector struct {
	Threshold    float64
	SustainTicks int
	counters     map[lockIdentity]int
	firstSeen    map[lockIdentity]collector.ObservationWindow
	fired        map[lockIdentity]bool
}

func NewLockDetector(threshold float64, sustain int) *LockDetector {
	if sustain < 1 {
		sustain = 1
	}
	return &LockDetector{
		Threshold:    threshold,
		SustainTicks: sustain,
		counters:     make(map[lockIdentity]int),
		firstSeen:    make(map[lockIdentity]collector.ObservationWindow),
		fired:        make(map[lockIdentity]bool),
	}
}

func (d *LockDetector) Detect(samples []collector.LockSample) []LockSignal {
	active := make(map[lockIdentity]bool, len(samples))
	var signals []LockSignal
	for _, sample := range samples {
		// A single FUTEX_WAIT only proves synchronization (for example an idle
		// condition-variable waiter), not contention. Require at least two
		// distinct waiting TIDs in the same instance/window before assigning the
		// stable lock.futex_contention root-cause code.
		if !sample.Window.Valid() || sample.OffcpuRatio < d.Threshold ||
			(sample.Futex && sample.WaiterCount < 2) {
			continue
		}
		key := identityOfLock(sample)
		active[key] = true
		if d.counters[key] == 0 {
			d.firstSeen[key] = sample.Window
		}
		d.counters[key]++
		if d.counters[key] >= d.SustainTicks && !d.fired[key] {
			d.fired[key] = true
			signals = append(signals, LockSignal{Sample: sample, Window: d.firstSeen[key].Extend(sample.Window)})
		}
	}
	for key := range d.counters {
		if !active[key] {
			delete(d.counters, key)
			delete(d.firstSeen, key)
			delete(d.fired, key)
		}
	}
	return signals
}
