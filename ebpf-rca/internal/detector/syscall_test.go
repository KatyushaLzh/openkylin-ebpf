package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestSyscallDetectorIgnoresWaitingWallTime(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Window:        testObservationWindow(time.Unix(0, 0), time.Second),
		Pid:           100,
		Nr:            232,
		Syscall:       "epoll_wait",
		CallsPerSec:   10,
		AvgLatUs:      90000,
		TotalMsPerSec: 900,
	}}
	if got := d.Detect(samples); len(got) != 0 {
		t.Fatalf("waiting syscall with low rate should not trigger, got %d", len(got))
	}
}

func TestSyscallDetectorIgnoresOrdinaryBlockingRead(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Window:        testObservationWindow(time.Unix(0, 0), time.Second),
		Pid:           100,
		Nr:            0,
		Syscall:       "read",
		CallsPerSec:   4,
		AvgLatUs:      250000,
		TotalMsPerSec: 1000,
	}}
	if got := d.Detect(samples); len(got) != 0 {
		t.Fatalf("low-rate blocking read is normal I/O wait, got %d signals", len(got))
	}
}

func TestSyscallDetectorReportsWaitingHighRate(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Window:        testObservationWindow(time.Unix(0, 0), time.Second),
		Pid:           100,
		Nr:            232,
		Syscall:       "epoll_wait",
		CallsPerSec:   1200,
		AvgLatUs:      50,
		TotalMsPerSec: 60,
	}}
	if got := d.Detect(samples); len(got) != 1 {
		t.Fatalf("waiting syscall with high rate should trigger, got %d", len(got))
	}
}

func TestSyscallDetectorReportsNonWaitingHighTotalTime(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Window:        testObservationWindow(time.Unix(0, 0), time.Second),
		Pid:           100,
		Nr:            74,
		Syscall:       "fsync",
		CallsPerSec:   20,
		AvgLatUs:      20000,
		TotalMsPerSec: syscallTimeMsPerSecFloor + 1,
	}}
	if got := d.Detect(samples); len(got) != 1 {
		t.Fatalf("non-waiting syscall with high total time should trigger, got %d", len(got))
	}
}

func TestSyscallDetectorIgnoresSelfComm(t *testing.T) {
	d := NewSyscallDetector(1, 1)
	samples := []collector.SyscallSample{{
		Window:      testObservationWindow(time.Unix(0, 0), time.Second),
		Pid:         100,
		Comm:        "ebpf-rca",
		Nr:          0,
		Syscall:     "read",
		CallsPerSec: 100000,
	}}
	if got := d.Detect(samples); len(got) != 0 {
		t.Fatalf("self syscall sample should be ignored, got %d", len(got))
	}
}

func TestSyscallDetectorUsesMeasuredWindow(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	now := time.Unix(10, 0)
	got := d.Detect([]collector.SyscallSample{{
		Window: collector.NewObservationWindow(now, 1250*time.Millisecond), Pid: 100, Nr: 0, Syscall: "read", CallsPerSec: 2000,
	}})
	if len(got) != 1 {
		t.Fatalf("expected one signal, got %#v", got)
	}
	if want := now.Add(-1250 * time.Millisecond); !got[0].Window.Start.Equal(want) {
		t.Fatalf("window start = %v, want %v", got[0].Window.Start, want)
	}
}
