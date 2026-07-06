package detector

import (
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
)

// MemSignal 表示一次已确认的内存抖动 / 回收压力异常。
type MemSignal struct {
	Snapshot    collector.MemSnapshot
	Culprit     collector.MemProc // 主要肇事进程（直接回收最多者）
	WindowStart time.Time
	WindowEnd   time.Time
}

// MemDetector 检测"可用内存持续低于阈值"的系统级内存压力。
type MemDetector struct {
	AvailPctFloor float64 // 可用内存占比下限(%)
	SustainTicks  int
	count         int
	firstSeen     time.Time
	fired         bool
}

// NewMemDetector 构造检测器（阈值单位为百分比）。
func NewMemDetector(availPctFloor float64, sustain int) *MemDetector {
	if sustain < 1 {
		sustain = 1
	}
	return &MemDetector{AvailPctFloor: availPctFloor, SustainTicks: sustain}
}

// Detect 处理一个窗口的内存快照，返回新触发的异常信号（0 或 1 个）。
func (d *MemDetector) Detect(snap collector.MemSnapshot, now time.Time) []MemSignal {
	if snap.MemAvailablePct >= d.AvailPctFloor || snap.MemTotalKB == 0 {
		d.count = 0
		d.fired = false
		return nil
	}
	if d.count == 0 {
		d.firstSeen = now
	}
	d.count++
	if d.count >= d.SustainTicks && !d.fired {
		d.fired = true
		return []MemSignal{{
			Snapshot:    snap,
			Culprit:     pickCulprit(snap),
			WindowStart: d.firstSeen,
			WindowEnd:   now,
		}}
	}
	return nil
}

// pickCulprit 选取压力贡献最大的进程：优先直接回收次数，其次 major fault。
func pickCulprit(snap collector.MemSnapshot) collector.MemProc {
	var best collector.MemProc
	for _, p := range snap.Procs {
		if p.DirectReclaimCount > best.DirectReclaimCount ||
			(p.DirectReclaimCount == best.DirectReclaimCount && p.MajFlt > best.MajFlt) {
			best = p
		}
	}
	return best
}
