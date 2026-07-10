package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestLockDetectorUsesMeasuredWindowAndInstanceIdentity(t *testing.T) {
	d := NewLockDetector(0.3, 1)
	now := time.Unix(10, 0)
	w := collector.NewObservationWindow(now, 1500*time.Millisecond)
	samples := []collector.LockSample{
		{Window: w, Pid: 10, Tid: 11, LockAddress: 0x1000, Futex: true, WaiterCount: 2, OffcpuRatio: 0.9},
		{Window: w, Pid: 10, Tid: 12, LockAddress: 0x2000, Futex: true, WaiterCount: 2, OffcpuRatio: 0.8},
	}
	got := d.Detect(samples)
	if len(got) != 2 {
		t.Fatalf("two lock instances in one process must remain distinct, got %#v", got)
	}
	for _, signal := range got {
		if want := now.Add(-1500 * time.Millisecond); !signal.Window.Start.Equal(want) {
			t.Fatalf("window start = %v, want %v", signal.Window.Start, want)
		}
	}
}

func TestLockDetectorRejectsSingleNormalFutexWaiter(t *testing.T) {
	d := NewLockDetector(0.3, 2)
	now := time.Unix(20, 0)
	for tick := 0; tick < 4; tick++ {
		w := collector.NewObservationWindow(now.Add(time.Duration(tick)*time.Second), time.Second)
		got := d.Detect([]collector.LockSample{{
			Window: w, Pid: 20, Tid: 21, LockAddress: 0x3000,
			Futex: true, WaiterCount: 1, OffcpuRatio: 0.95,
		}})
		if len(got) != 0 {
			t.Fatalf("single condition-variable/futex waiter must not be called contention: %#v", got)
		}
	}
}
