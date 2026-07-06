package detector

import (
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
)

// 单个 syscall 累计耗时超过该比例(ms/秒)视为"高耗时热点"，与高频热点并列触发。
const syscallTimeMsPerSecFloor = 300.0

// SyscallSignal 表示一次已确认的系统调用热点异常。
type SyscallSignal struct {
	Sample      collector.SyscallSample
	WindowStart time.Time
	WindowEnd   time.Time
}

// SyscallDetector 检测高频或高耗时的 (进程, syscall) 热点。
type SyscallDetector struct {
	CallsPerSecFloor float64
	SustainTicks     int
	counters         map[uint64]int
	firstSeen        map[uint64]time.Time
	fired            map[uint64]bool
}

// NewSyscallDetector 构造检测器（阈值为每秒调用次数）。
func NewSyscallDetector(callsPerSecFloor float64, sustain int) *SyscallDetector {
	if sustain < 1 {
		sustain = 1
	}
	return &SyscallDetector{
		CallsPerSecFloor: callsPerSecFloor,
		SustainTicks:     sustain,
		counters:         make(map[uint64]int),
		firstSeen:        make(map[uint64]time.Time),
		fired:            make(map[uint64]bool),
	}
}

func scSigKey(pid, nr uint32) uint64 { return uint64(pid)<<32 | uint64(nr) }

// Detect 处理一个窗口的样本，返回本窗口新触发的热点信号。
func (d *SyscallDetector) Detect(samples []collector.SyscallSample, now time.Time) []SyscallSignal {
	active := make(map[uint64]bool, len(samples))
	var signals []SyscallSignal

	for _, s := range samples {
		hot := s.CallsPerSec >= d.CallsPerSecFloor || s.TotalMsPerSec >= syscallTimeMsPerSecFloor
		if !hot {
			continue
		}
		k := scSigKey(s.Pid, s.Nr)
		active[k] = true
		if d.counters[k] == 0 {
			d.firstSeen[k] = now
		}
		d.counters[k]++
		if d.counters[k] >= d.SustainTicks && !d.fired[k] {
			d.fired[k] = true
			signals = append(signals, SyscallSignal{
				Sample:      s,
				WindowStart: d.firstSeen[k],
				WindowEnd:   now,
			})
		}
	}

	for k := range d.counters {
		if !active[k] {
			delete(d.counters, k)
			delete(d.firstSeen, k)
			delete(d.fired, k)
		}
	}
	return signals
}
