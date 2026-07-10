package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestCPUDetectsProcessAggregateAndPreservesMeasuredWindow(t *testing.T) {
	d := NewCPUDetector(0.8, 2)
	t0 := time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
	first := collector.Sample{Pid: 10, Tid: 11, CPUUtil: 0.5, ProcessCPUCores: 1.2,
		Window: testObservationWindow(t0, time.Second)}
	second := first
	second.Window = testObservationWindow(first.Window.End, 1500*time.Millisecond)
	if got := d.Detect([]collector.Sample{first}); len(got) != 0 {
		t.Fatalf("first window fired: %+v", got)
	}
	got := d.Detect([]collector.Sample{second})
	if len(got) != 1 {
		t.Fatalf("signals=%d, want 1", len(got))
	}
	if !got[0].Window.Start.Equal(t0) || !got[0].Window.End.Equal(second.Window.End) {
		t.Fatalf("window=%s..%s", got[0].Window.Start, got[0].Window.End)
	}
}

func TestCPUDetectsSingleHotThread(t *testing.T) {
	d := NewCPUDetector(0.8, 1)
	s := collector.Sample{Pid: 10, Tid: 12, CPUUtil: 0.9, ProcessCPUCores: 0.9,
		Window: testObservationWindow(time.Now(), time.Second)}
	if got := d.Detect([]collector.Sample{s}); len(got) != 1 {
		t.Fatalf("signals=%d, want 1", len(got))
	}
}

func testObservationWindow(start time.Time, elapsed time.Duration) collector.ObservationWindow {
	return collector.ObservationWindowBetween(start, start.Add(elapsed))
}
