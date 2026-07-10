package rca

import (
	"strings"
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func TestCPUHighContextSwitchDoesNotInferLock(t *testing.T) {
	report := BuildCPUReport(detector.Signal{Sample: collector.Sample{
		Pid: 20, Tid: 21, CPUUtil: 0.9, ProcessCPUCores: 0.9, CtxPerMin: 1e6,
	}, Window: rcaTestWindow()}, 0.8)
	if report.RootCauseCode != schema.RootCauseCPUComputeHotspot {
		t.Fatalf("root cause code=%q", report.RootCauseCode)
	}
	if strings.Contains(report.SuspectedRootCause, "锁") {
		t.Fatalf("unsupported lock inference: %q", report.SuspectedRootCause)
	}
}

func TestCPUReportUsesTGIDAndHottestTID(t *testing.T) {
	report := BuildCPUReport(detector.Signal{Sample: collector.Sample{
		Pid: 30, Tid: 33, CPUUtil: 0.8, ProcessCPUCores: 1.6,
	}, Window: rcaTestWindow()}, 0.8)
	if report.RelatedObject.Pid != 30 || report.RelatedObject.Tid != 33 {
		t.Fatalf("object=%+v", report.RelatedObject)
	}
}

func TestIOCongestionUsesTimeWeightedAverage(t *testing.T) {
	base := detector.IOSignal{Sample: collector.IOSample{DevName: "8:0 sda", P99LatMs: 20,
		QueueDepth: 64, AverageQueueDepth: 2}, Window: rcaTestWindow()}
	if got := BuildIOReport(base, 10).RootCauseCode; got != schema.RootCauseIODeviceLatency {
		t.Fatalf("current-depth spike classified as congestion: %q", got)
	}
	base.Sample.AverageQueueDepth = 16
	if got := BuildIOReport(base, 10).RootCauseCode; got != schema.RootCauseIOQueueCongestion {
		t.Fatalf("sustained queue not classified as congestion: %q", got)
	}
}

func TestTimeWindowDoesNotFabricateOneSecond(t *testing.T) {
	when := time.Unix(2, 123)
	w := timeWindow(collector.ObservationWindow{Start: when, End: when})
	if w.ElapsedMS != 0 || w.Start != w.End {
		t.Fatalf("fabricated window: %+v", w)
	}
}

func rcaTestWindow() collector.ObservationWindow {
	return collector.ObservationWindowBetween(time.Unix(1, 0), time.Unix(2, 0))
}
