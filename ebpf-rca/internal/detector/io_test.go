package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestIODetectorUsesMeasuredWindow(t *testing.T) {
	d := NewIODetector(10, 1)
	start := time.Date(2026, 7, 10, 2, 0, 0, 0, time.UTC)
	end := start.Add(1750 * time.Millisecond)
	s := collector.IOSample{Dev: 1, P99LatMs: 12, Window: collector.ObservationWindowBetween(start, end)}
	got := d.Detect([]collector.IOSample{s})
	if len(got) != 1 {
		t.Fatalf("signals=%d, want 1", len(got))
	}
	if !got[0].Window.Start.Equal(start) || !got[0].Window.End.Equal(end) {
		t.Fatalf("window=%s..%s", got[0].Window.Start, got[0].Window.End)
	}
}
