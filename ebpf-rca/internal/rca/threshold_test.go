package rca

import (
	"testing"
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
	"github.com/os2026/ebpf-rca/internal/detector"
)

func TestCPUReportUsesRuntimeThreshold(t *testing.T) {
	threshold := 0.73
	report := BuildCPUReport(detector.Signal{
		Sample: collector.Sample{
			Pid:     100,
			Comm:    "hot",
			CPUUtil: 0.88,
		},
		WindowStart: time.Unix(1, 0),
		WindowEnd:   time.Unix(2, 0),
	}, threshold)
	if len(report.EvidenceChain) == 0 {
		t.Fatal("missing evidence")
	}
	if got := report.EvidenceChain[0].Threshold; got != threshold {
		t.Fatalf("threshold = %#v, want %#v", got, threshold)
	}
}

func TestMemReportOmitsEmptyCulpritObject(t *testing.T) {
	report := BuildMemReport(detector.MemSignal{
		Snapshot: collector.MemSnapshot{
			MemTotalKB:      100,
			MemAvailablePct: 10,
		},
		WindowStart: time.Unix(1, 0),
		WindowEnd:   time.Unix(2, 0),
	}, 15)
	if report.RelatedObject.Pid != 0 || report.RelatedObject.Comm != "" {
		t.Fatalf("empty culprit should produce system object, got %#v", report.RelatedObject)
	}
}
