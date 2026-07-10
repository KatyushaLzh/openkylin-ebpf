package syscalls

import "testing"

func TestArchitectureSpecificTables(t *testing.T) {
	tests := []struct {
		arch string
		nr   uint32
		want string
	}{
		{"amd64", 0, "read"},
		{"amd64", 202, "futex"},
		{"amd64", 455, "futex_wait"},
		{"arm64", 63, "read"},
		{"arm64", 98, "futex"},
		{"arm64", 451, "cachestat"},
		{"riscv64", 63, "read"},
		{"riscv64", 258, "riscv_hwprobe"},
		{"riscv64", 259, "riscv_flush_icache"},
		{"riscv64", 38, "syscall_38"},
	}
	for _, tt := range tests {
		if got := NameForArch(tt.arch, tt.nr); got != tt.want {
			t.Errorf("NameForArch(%q, %d) = %q, want %q", tt.arch, tt.nr, got, tt.want)
		}
	}
}

func TestWaitingClassificationCoversModernAndSocketWaits(t *testing.T) {
	for _, name := range []string{"epoll_pwait2", "futex_wait", "io_uring_enter", "accept4", "recvmsg", "read", "write", "sendmsg"} {
		if !IsWaitingName(name) {
			t.Errorf("%s should be classified as waiting", name)
		}
	}
	if IsWaitingName("fsync") {
		t.Fatal("fsync latency should remain diagnosable")
	}
}
