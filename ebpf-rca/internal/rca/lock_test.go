package rca

import (
	"strings"
	"testing"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func TestStackHasLockIncludesFileLocks(t *testing.T) {
	stack := []string{"schedule", "locks_lock_inode_wait", "do_flock"}
	if !StackHasLock(stack) {
		t.Fatalf("file lock stack should be classified as lock: %#v", stack)
	}
}

func TestStackHasLockRejectsPlainPollSleep(t *testing.T) {
	stack := []string{"schedule_timeout", "do_poll", "sys_epoll_wait"}
	if StackHasLock(stack) {
		t.Fatalf("plain poll/sleep stack should not be classified as lock: %#v", stack)
	}
}

func TestFutexReportUsesAddressAndDoesNotCallWakerOwner(t *testing.T) {
	report := BuildLockReport(detector.LockSignal{
		Sample: collector.LockSample{
			Pid: 10, Tid: 11, Comm: "waiter", Futex: true, LockAddress: 0x1234,
			LastWaker: 12, WaiterCount: 2, OffcpuRatio: 0.8,
		},
		Window: rcaTestWindow(),
	}, nil, 0.3)
	if report.RootCauseCode != schema.RootCauseLockFutexContention || report.RelatedObject.LockAddress != 0x1234 {
		t.Fatalf("unexpected futex report: %#v", report)
	}
	if strings.Contains(report.SuspectedRootCause+report.Suggestion, "持锁者") {
		t.Fatalf("waker must not be described as owner: %s / %s", report.SuspectedRootCause, report.Suggestion)
	}
}
