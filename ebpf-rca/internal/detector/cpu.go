// Package detector 对采样指标做时序异常判定。
//
// 当前实现采用"持续高占用"规则（阈值 + 连续窗口数），保证零幻觉、可解释。
// 后续可在此扩展 EWMA / 3-sigma / Spectral Residual 等检测算法。
package detector

import (
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

// Signal 表示一次已确认的异常信号。
type Signal struct {
	Sample      collector.Sample
	WindowStart time.Time
	WindowEnd   time.Time
}

// CPUDetector 检测持续的高 CPU 占用线程。
type CPUDetector struct {
	Threshold    float64 // CPU 占用阈值（单核占比）
	SustainTicks int     // 连续超过阈值多少个窗口才触发
	counters     map[uint32]int
	firstSeen    map[uint32]time.Time
	fired        map[uint32]bool
}

// NewCPUDetector 构造检测器。
func NewCPUDetector(threshold float64, sustain int) *CPUDetector {
	if sustain < 1 {
		sustain = 1
	}
	return &CPUDetector{
		Threshold:    threshold,
		SustainTicks: sustain,
		counters:     make(map[uint32]int),
		firstSeen:    make(map[uint32]time.Time),
		fired:        make(map[uint32]bool),
	}
}

// Detect 处理一个窗口的样本，返回本窗口新触发的异常信号。
func (d *CPUDetector) Detect(samples []collector.Sample, now time.Time) []Signal {
	active := make(map[uint32]bool, len(samples))
	var signals []Signal

	for _, s := range samples {
		if s.CPUUtil < d.Threshold {
			continue
		}
		active[s.Pid] = true
		if d.counters[s.Pid] == 0 {
			d.firstSeen[s.Pid] = now
		}
		d.counters[s.Pid]++
		if d.counters[s.Pid] >= d.SustainTicks && !d.fired[s.Pid] {
			d.fired[s.Pid] = true
			signals = append(signals, Signal{
				Sample:      s,
				WindowStart: d.firstSeen[s.Pid],
				WindowEnd:   now,
			})
		}
	}

	// 本窗口回落到阈值以下的线程，重置其状态（允许下次重新触发）。
	for pid := range d.counters {
		if !active[pid] {
			delete(d.counters, pid)
			delete(d.firstSeen, pid)
			delete(d.fired, pid)
		}
	}
	return signals
}
