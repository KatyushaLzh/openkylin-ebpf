package rca

import "testing"

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
