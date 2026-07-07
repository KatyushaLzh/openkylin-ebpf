package detector

import (
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

// MemSignal 表示一次已确认的内存抖动 / 回收压力异常。
type MemSignal struct {
	Snapshot    collector.MemSnapshot
	Culprit     collector.MemProc // 主要肇事进程（按 direct reclaim / major fault / RSS 增长优先级选取）
	WindowStart time.Time
	WindowEnd   time.Time
}

// MemDetector 检测低可用内存或直接回收、kswapd、major fault、RSS 增长等强内存压力信号。
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
	if !hasMemPressureSignal(snap, d.AvailPctFloor) {
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

func hasMemPressureSignal(snap collector.MemSnapshot, availPctFloor float64) bool {
	if snap.MemTotalKB > 0 && snap.MemAvailablePct < availPctFloor {
		return true
	}
	if snap.KswapdWakes > 0 {
		return true
	}
	for _, p := range snap.Procs {
		if p.DirectReclaimCount > 0 || p.MajFlt > 0 || hasRSSGrowthSignal(p) {
			return true
		}
	}
	return false
}

func hasRSSGrowthSignal(p collector.MemProc) bool {
	return p.RSSDeltaKB >= collector.MemRSSGrowthSignalKB ||
		p.AnonRSSDeltaKB >= collector.MemRSSGrowthSignalKB
}

// pickCulprit 选取压力贡献最大的进程：direct reclaim > major fault > RSS/AnonRSS 增长 > 最大 RSS。
func pickCulprit(snap collector.MemSnapshot) collector.MemProc {
	var best collector.MemProc
	for _, p := range snap.Procs {
		if p.DirectReclaimCount > 0 &&
			(p.DirectReclaimCount > best.DirectReclaimCount ||
				(p.DirectReclaimCount == best.DirectReclaimCount && p.DirectReclaimMs > best.DirectReclaimMs)) {
			best = p
		}
	}
	if best.Pid != 0 {
		return best
	}
	for _, p := range snap.Procs {
		if p.MajFlt > 0 && p.MajFlt > best.MajFlt {
			best = p
		}
	}
	if best.Pid != 0 {
		return best
	}
	for _, p := range snap.Procs {
		if !hasRSSGrowthSignal(p) {
			continue
		}
		if p.AnonRSSDeltaKB > best.AnonRSSDeltaKB ||
			(p.AnonRSSDeltaKB == best.AnonRSSDeltaKB && p.RSSDeltaKB > best.RSSDeltaKB) {
			best = p
		}
	}
	if best.Pid == 0 {
		best = snap.TopRSSProc
	}
	return best
}
