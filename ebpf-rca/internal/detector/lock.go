package detector

import (
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
)

// LockSignal 表示一次已确认的锁竞争/长阻塞异常。
type LockSignal struct {
	Sample      collector.LockSample
	WindowStart time.Time
	WindowEnd   time.Time
}

// LockDetector 检测持续高 off-CPU 阻塞占比的线程。
type LockDetector struct {
	Threshold    float64 // off-CPU 阻塞占比阈值(0..1)
	SustainTicks int
	counters     map[uint32]int
	firstSeen    map[uint32]time.Time
	fired        map[uint32]bool
}

// NewLockDetector 构造检测器。
func NewLockDetector(threshold float64, sustain int) *LockDetector {
	if sustain < 1 {
		sustain = 1
	}
	return &LockDetector{
		Threshold:    threshold,
		SustainTicks: sustain,
		counters:     make(map[uint32]int),
		firstSeen:    make(map[uint32]time.Time),
		fired:        make(map[uint32]bool),
	}
}

// Detect 处理一个窗口的样本，返回本窗口新触发的异常信号。
func (d *LockDetector) Detect(samples []collector.LockSample, now time.Time) []LockSignal {
	active := make(map[uint32]bool, len(samples))
	var signals []LockSignal

	for _, s := range samples {
		if s.OffcpuRatio < d.Threshold {
			continue
		}
		active[s.Pid] = true
		if d.counters[s.Pid] == 0 {
			d.firstSeen[s.Pid] = now
		}
		d.counters[s.Pid]++
		if d.counters[s.Pid] >= d.SustainTicks && !d.fired[s.Pid] {
			d.fired[s.Pid] = true
			signals = append(signals, LockSignal{
				Sample:      s,
				WindowStart: d.firstSeen[s.Pid],
				WindowEnd:   now,
			})
		}
	}

	for pid := range d.counters {
		if !active[pid] {
			delete(d.counters, pid)
			delete(d.firstSeen, pid)
			delete(d.fired, pid)
		}
	}
	return signals
}
