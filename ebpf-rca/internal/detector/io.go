package detector

import "github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"

// IOSignal 表示一次已确认的 I/O 延迟抖动异常。
type IOSignal struct {
	Sample collector.IOSample
	Window collector.ObservationWindow
}

// IODetector 检测 P99 时延持续超阈值的块设备。
type IODetector struct {
	P99ThresholdMs float64
	SustainTicks   int
	counters       map[uint32]int
	firstSeen      map[uint32]collector.ObservationWindow
	fired          map[uint32]bool
}

// NewIODetector 构造检测器（阈值单位为毫秒）。
func NewIODetector(p99ThresholdMs float64, sustain int) *IODetector {
	if sustain < 1 {
		sustain = 1
	}
	return &IODetector{
		P99ThresholdMs: p99ThresholdMs,
		SustainTicks:   sustain,
		counters:       make(map[uint32]int),
		firstSeen:      make(map[uint32]collector.ObservationWindow),
		fired:          make(map[uint32]bool),
	}
}

// Detect 处理一个窗口的样本，返回本窗口新触发的异常信号。
func (d *IODetector) Detect(samples []collector.IOSample) []IOSignal {
	active := make(map[uint32]bool, len(samples))
	var signals []IOSignal

	for _, s := range samples {
		if !s.Window.Valid() || s.P99LatMs < d.P99ThresholdMs {
			continue
		}
		active[s.Dev] = true
		if d.counters[s.Dev] == 0 {
			d.firstSeen[s.Dev] = s.Window
		}
		d.counters[s.Dev]++
		if d.counters[s.Dev] >= d.SustainTicks && !d.fired[s.Dev] {
			d.fired[s.Dev] = true
			signals = append(signals, IOSignal{Sample: s, Window: d.firstSeen[s.Dev].Extend(s.Window)})
		}
	}

	for dev := range d.counters {
		if !active[dev] {
			delete(d.counters, dev)
			delete(d.firstSeen, dev)
			delete(d.fired, dev)
		}
	}
	return signals
}
