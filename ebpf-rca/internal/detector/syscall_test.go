package detector

import (
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestSyscallDetectorIgnoresWaitingWallTime(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Pid:           100,
		Nr:            232,
		Syscall:       "epoll_wait",
		CallsPerSec:   10,
		AvgLatUs:      90000,
		TotalMsPerSec: 900,
	}}
	if got := d.Detect(samples, time.Unix(1, 0)); len(got) != 0 {
		t.Fatalf("waiting syscall with low rate should not trigger, got %d", len(got))
	}
}

func TestSyscallDetectorReportsWaitingHighRate(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Pid:           100,
		Nr:            232,
		Syscall:       "epoll_wait",
		CallsPerSec:   1200,
		AvgLatUs:      50,
		TotalMsPerSec: 60,
	}}
	if got := d.Detect(samples, time.Unix(1, 0)); len(got) != 1 {
		t.Fatalf("waiting syscall with high rate should trigger, got %d", len(got))
	}
}

func TestSyscallDetectorReportsNonWaitingHighTotalTime(t *testing.T) {
	d := NewSyscallDetector(1000, 1)
	samples := []collector.SyscallSample{{
		Pid:           100,
		Nr:            74,
		Syscall:       "fsync",
		CallsPerSec:   20,
		AvgLatUs:      20000,
		TotalMsPerSec: syscallTimeMsPerSecFloor + 1,
	}}
	if got := d.Detect(samples, time.Unix(1, 0)); len(got) != 1 {
		t.Fatalf("non-waiting syscall with high total time should trigger, got %d", len(got))
	}
}

func TestSyscallDetectorIgnoresSelfComm(t *testing.T) {
	d := NewSyscallDetector(1, 1)
	samples := []collector.SyscallSample{{
		Pid:         100,
		Comm:        "ebpf-rca",
		Nr:          0,
		Syscall:     "read",
		CallsPerSec: 100000,
	}}
	if got := d.Detect(samples, time.Unix(1, 0)); len(got) != 0 {
		t.Fatalf("self syscall sample should be ignored, got %d", len(got))
	}
}
