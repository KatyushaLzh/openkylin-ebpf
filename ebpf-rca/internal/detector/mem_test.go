package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestMemDetectorRequiresSystemPressureAndContribution(t *testing.T) {
	d := NewMemDetector(15, 1)
	contributor := collector.MemProc{Pid: 101, MajFltPerSec: collector.MemMajorFaultSignalPerSec}
	w := testObservationWindow(time.Unix(0, 0), time.Second)

	if got := d.Detect(collector.MemSnapshot{Window: w, Procs: []collector.MemProc{contributor}}); len(got) != 0 {
		t.Fatalf("process contribution without system pressure triggered: %#v", got)
	}
	if got := d.Detect(collector.MemSnapshot{
		Window: w, MemTotalKB: 100, MemAvailablePct: 10,
	}); len(got) != 0 {
		t.Fatalf("low available memory without a contributor triggered: %#v", got)
	}
	got := d.Detect(collector.MemSnapshot{
		Window: w, MemTotalKB: 100, MemAvailablePct: 10, Procs: []collector.MemProc{contributor},
	})
	if len(got) != 1 || got[0].Culprit.Pid != 101 {
		t.Fatalf("combined pressure should identify contributor 101, got %#v", got)
	}
}

func TestMemDetectorDoesNotTriggerOnKswapdOrSingleMajorFault(t *testing.T) {
	d := NewMemDetector(15, 1)
	snap := collector.MemSnapshot{
		Window:     testObservationWindow(time.Unix(0, 0), time.Second),
		MemTotalKB: 100, MemAvailablePct: 80, KswapdWakes: 1,
		Procs: []collector.MemProc{{Pid: 102, MajFlt: 1, MajFltPerSec: 1}},
	}
	if got := d.Detect(snap); len(got) != 0 {
		t.Fatalf("auxiliary-only evidence must not trigger, got %#v", got)
	}
}

func TestMemDetectorOOMBypassesSustain(t *testing.T) {
	d := NewMemDetector(15, 5)
	now := time.Unix(10, 0)
	snap := collector.MemSnapshot{
		Window:         collector.NewObservationWindow(now, 2*time.Second),
		OOMVictimCount: 1,
		OOMVictims:     []collector.MemProc{{Pid: 103, Comm: "victim", OOMVictimCount: 1}},
	}
	got := d.Detect(snap)
	if len(got) != 1 || !got[0].OOM || got[0].Culprit.Pid != 103 {
		t.Fatalf("OOM should fire immediately with victim 103, got %#v", got)
	}
	if want := now.Add(-2 * time.Second); !got[0].Window.Start.Equal(want) {
		t.Fatalf("window start = %v, want measured %v", got[0].Window.Start, want)
	}
}

func TestMemDetectorTargetCanReportSystemScopeWithoutFakePID(t *testing.T) {
	d := NewMemDetector(15, 1)
	snap := collector.MemSnapshot{
		Window:             testObservationWindow(time.Unix(0, 0), time.Second),
		Targeted:           true,
		MemTotalKB:         100,
		MemAvailablePct:    10,
		GlobalContribution: true,
	}
	got := d.Detect(snap)
	if len(got) != 1 || got[0].Culprit.Pid != 0 {
		t.Fatalf("unattributed target-mode pressure must keep an empty culprit, got %#v", got)
	}
}

func TestPickMemCulpritUsesCausalPriority(t *testing.T) {
	snap := collector.MemSnapshot{Procs: []collector.MemProc{
		{Pid: 101, MajFltPerSec: 1000},
		{Pid: 102, AnonRSSGrowthKBPerSec: collector.MemAnonRSSGrowthSignalKBPerSec * 4},
		{Pid: 103, DirectReclaimCount: 1, DirectReclaimMs: 2},
	}}
	if got := pickCulprit(snap).Pid; got != 103 {
		t.Fatalf("direct reclaim should outrank other evidence, got pid %d", got)
	}
	snap.Procs = snap.Procs[:2]
	if got := pickCulprit(snap).Pid; got != 102 {
		t.Fatalf("anonymous growth should outrank major faults, got pid %d", got)
	}
	snap.Procs = snap.Procs[:1]
	if got := pickCulprit(snap).Pid; got != 101 {
		t.Fatalf("major-fault contributor should be selected, got pid %d", got)
	}
}
