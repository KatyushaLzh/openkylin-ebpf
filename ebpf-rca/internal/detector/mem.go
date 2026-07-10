package detector

import "github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"

type MemSignal struct {
	Snapshot collector.MemSnapshot
	Culprit  collector.MemProc
	OOM      bool
	Window   collector.ObservationWindow
}

type MemDetector struct {
	AvailPctFloor float64
	SustainTicks  int
	count         int
	firstSeen     collector.ObservationWindow
	fired         bool
}

func NewMemDetector(availPctFloor float64, sustain int) *MemDetector {
	if sustain < 1 {
		sustain = 1
	}
	return &MemDetector{AvailPctFloor: availPctFloor, SustainTicks: sustain}
}

func (d *MemDetector) Detect(snap collector.MemSnapshot) []MemSignal {
	if !snap.Window.Valid() {
		d.count = 0
		d.fired = false
		return nil
	}
	// mark_victim is an authoritative event and must not wait for sustain.
	if snap.OOMVictimCount > 0 {
		d.count = 0
		d.fired = false
		return []MemSignal{{
			Snapshot: snap,
			Culprit:  pickOOMVictim(snap.OOMVictims),
			OOM:      true,
			Window:   snap.Window,
		}}
	}

	if !hasOrdinaryMemPressure(snap, d.AvailPctFloor) {
		d.count = 0
		d.fired = false
		return nil
	}
	if d.count == 0 {
		d.firstSeen = snap.Window
	}
	d.count++
	if d.count >= d.SustainTicks && !d.fired {
		d.fired = true
		return []MemSignal{{
			Snapshot: snap,
			Culprit:  pickCulprit(snap),
			Window:   d.firstSeen.Extend(snap.Window),
		}}
	}
	return nil
}

func hasOrdinaryMemPressure(snap collector.MemSnapshot, availPctFloor float64) bool {
	systemPressure := (snap.MemTotalKB > 0 && snap.MemAvailablePct < availPctFloor) ||
		snap.PSISomePct >= collector.MemPSISomeSignalPct ||
		snap.PSIFullPct >= collector.MemPSIFullSignalPct ||
		snap.DirectReclaimMsPerSec >= collector.MemDirectReclaimSignalMsPerSec
	if !systemPressure {
		return false
	}
	if snap.GlobalContribution {
		return true
	}
	for _, proc := range snap.Procs {
		if isMemContributor(proc) {
			return true
		}
	}
	return false
}

func isMemContributor(proc collector.MemProc) bool {
	return proc.DirectReclaimCount > 0 || proc.DirectReclaimMs > 0 ||
		proc.AnonRSSGrowthKBPerSec >= collector.MemAnonRSSGrowthSignalKBPerSec ||
		proc.MajFltPerSec >= collector.MemMajorFaultSignalPerSec
}

func pickOOMVictim(victims []collector.MemProc) collector.MemProc {
	var best collector.MemProc
	for _, victim := range victims {
		if victim.OOMVictimCount > best.OOMVictimCount {
			best = victim
		}
	}
	return best
}

// Causality order: direct reclaim > anonymous working-set growth > major
// faults.  Merely being the largest RSS process is not causal evidence.
func pickCulprit(snap collector.MemSnapshot) collector.MemProc {
	var best collector.MemProc
	for _, proc := range snap.Procs {
		if proc.DirectReclaimCount == 0 && proc.DirectReclaimMs == 0 {
			continue
		}
		if proc.DirectReclaimMs > best.DirectReclaimMs ||
			(proc.DirectReclaimMs == best.DirectReclaimMs && proc.DirectReclaimCount > best.DirectReclaimCount) {
			best = proc
		}
	}
	if best.Pid != 0 {
		return best
	}
	for _, proc := range snap.Procs {
		if proc.AnonRSSGrowthKBPerSec >= collector.MemAnonRSSGrowthSignalKBPerSec &&
			proc.AnonRSSGrowthKBPerSec > best.AnonRSSGrowthKBPerSec {
			best = proc
		}
	}
	if best.Pid != 0 {
		return best
	}
	for _, proc := range snap.Procs {
		if proc.MajFltPerSec >= collector.MemMajorFaultSignalPerSec && proc.MajFltPerSec > best.MajFltPerSec {
			best = proc
		}
	}
	return best
}
