package rca

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
)

func TestCPUReportUsesRuntimeThreshold(t *testing.T) {
	threshold := 0.73
	report := BuildCPUReport(detector.Signal{
		Sample: collector.Sample{
			Pid:     100,
			Comm:    "hot",
			CPUUtil: 0.88,
		},
		Window: rcaTestWindow(),
	}, threshold)
	if len(report.EvidenceChain) == 0 {
		t.Fatal("missing evidence")
	}
	if got := report.EvidenceChain[0].Threshold; got != threshold {
		t.Fatalf("threshold = %#v, want %#v", got, threshold)
	}
}

func TestReportTimeWindowDoesNotInventElapsedTime(t *testing.T) {
	report := BuildSyscallReport(detector.SyscallSignal{
		Sample: collector.SyscallSample{
			Pid:         100,
			Comm:        "hot",
			Syscall:     "read",
			CallsPerSec: 2000,
		},
		Window: collector.ObservationWindow{Start: time.Unix(2, 0), End: time.Unix(2, 0)},
	}, 1000, 100)
	start, err := time.Parse(time.RFC3339, report.TimeWindow.Start)
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC3339, report.TimeWindow.End)
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(end) || report.TimeWindow.ElapsedMS != 0 {
		t.Fatalf("single instant must remain exact, got window=%+v", report.TimeWindow)
	}
}

func TestMemReportOmitsEmptyCulpritObject(t *testing.T) {
	report := BuildMemReport(detector.MemSignal{
		Snapshot: collector.MemSnapshot{
			MemTotalKB:      100,
			MemAvailablePct: 10,
		},
		Window: rcaTestWindow(),
	}, 15)
	if report.RelatedObject.Pid != 0 || report.RelatedObject.Comm != "" {
		t.Fatalf("empty culprit should produce system object, got %#v", report.RelatedObject)
	}
	if report.RelatedObject.Scope != "system" {
		t.Fatalf("empty culprit must be system-scoped, got %#v", report.RelatedObject)
	}
}

func TestMemOOMReportHasMachineCode(t *testing.T) {
	report := BuildMemReport(detector.MemSignal{
		OOM: true, Culprit: collector.MemProc{Pid: 9, Comm: "victim", OOMVictimCount: 1},
		Snapshot: collector.MemSnapshot{OOMVictimCount: 1},
		Window:   rcaTestWindow(),
	}, 15)
	if report.RootCauseCode != "mem.oom_victim" || report.RelatedObject.Pid != 9 {
		t.Fatalf("unexpected OOM report: %#v", report)
	}
}
