package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestMemDetectorTriggersOnDirectReclaim(t *testing.T) {
	d := NewMemDetector(15, 1)
	snap := collector.MemSnapshot{
		MemTotalKB:      100,
		MemAvailablePct: 80,
		Procs: []collector.MemProc{{
			Pid:                101,
			DirectReclaimCount: 1,
		}},
	}
	signals := d.Detect(snap, time.Unix(1, 0))
	if len(signals) != 1 || signals[0].Culprit.Pid != 101 {
		t.Fatalf("direct reclaim should trigger with culprit 101, got %#v", signals)
	}
}

func TestMemDetectorTriggersOnMajorFault(t *testing.T) {
	d := NewMemDetector(15, 1)
	snap := collector.MemSnapshot{
		MemTotalKB:      100,
		MemAvailablePct: 80,
		Procs: []collector.MemProc{{
			Pid:    102,
			MajFlt: 3,
		}},
	}
	signals := d.Detect(snap, time.Unix(1, 0))
	if len(signals) != 1 || signals[0].Culprit.Pid != 102 {
		t.Fatalf("major fault should trigger with culprit 102, got %#v", signals)
	}
}

func TestMemDetectorTriggersOnRSSGrowth(t *testing.T) {
	d := NewMemDetector(15, 1)
	snap := collector.MemSnapshot{
		MemTotalKB:      100,
		MemAvailablePct: 80,
		Procs: []collector.MemProc{{
			Pid:            103,
			AnonRSSDeltaKB: collector.MemRSSGrowthSignalKB,
		}},
	}
	signals := d.Detect(snap, time.Unix(1, 0))
	if len(signals) != 1 || signals[0].Culprit.Pid != 103 {
		t.Fatalf("RSS growth should trigger with culprit 103, got %#v", signals)
	}
}

func TestPickMemCulpritPriority(t *testing.T) {
	snap := collector.MemSnapshot{
		TopRSSProc: collector.MemProc{Pid: 400, RSSKB: 1 << 20},
		Procs: []collector.MemProc{
			{Pid: 101, MajFlt: 1000},
			{Pid: 102, AnonRSSDeltaKB: collector.MemRSSGrowthSignalKB * 4},
			{Pid: 103, DirectReclaimCount: 1},
		},
	}
	if got := pickCulprit(snap).Pid; got != 103 {
		t.Fatalf("direct reclaim should outrank other signals, got pid %d", got)
	}

	snap.Procs = snap.Procs[:2]
	if got := pickCulprit(snap).Pid; got != 101 {
		t.Fatalf("major fault should outrank RSS growth, got pid %d", got)
	}

	snap.Procs = snap.Procs[1:2]
	if got := pickCulprit(snap).Pid; got != 102 {
		t.Fatalf("RSS growth should outrank top RSS fallback, got pid %d", got)
	}

	snap.Procs = nil
	if got := pickCulprit(snap).Pid; got != 400 {
		t.Fatalf("top RSS should be fallback culprit, got pid %d", got)
	}
}
