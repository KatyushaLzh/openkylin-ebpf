// Package syscalls 将 syscall 号解析为名称。
//
// syscall 号随架构而异：amd64 用其专有表，arm64/riscv64 用 asm-generic 表。
// 这里内置性能相关常见 syscall 的子集，未命中时回退为 "syscall_<nr>"。
// 表可由内核头文件(unistd_64.h / asm-generic/unistd.h) 重新生成以求完整。
package syscalls

import (
	"fmt"
	"runtime"
)

// amd64 常见/性能相关 syscall 表（x86_64 unistd_64.h）。
var amd64 = map[uint32]string{
	0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
	7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap", 12: "brk",
	13: "rt_sigaction", 14: "rt_sigprocmask", 16: "ioctl", 17: "pread64",
	18: "pwrite64", 19: "readv", 20: "writev", 21: "access", 22: "pipe",
	23: "select", 24: "sched_yield", 28: "madvise", 32: "dup", 33: "dup2",
	35: "nanosleep", 39: "getpid", 41: "socket", 42: "connect", 43: "accept",
	44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg", 56: "clone",
	57: "fork", 59: "execve", 60: "exit", 61: "wait4", 62: "kill", 72: "fcntl",
	73: "flock", 74: "fsync", 75: "fdatasync", 78: "getdents", 82: "rename",
	83: "mkdir", 87: "unlink", 89: "readlink", 96: "gettimeofday",
	101: "ptrace", 102: "getuid", 157: "prctl", 158: "arch_prctl",
	202: "futex", 213: "epoll_create", 217: "getdents64", 228: "clock_gettime",
	230: "clock_nanosleep", 232: "epoll_wait", 233: "epoll_ctl", 257: "openat",
	262: "newfstatat", 270: "pselect6", 271: "ppoll", 281: "epoll_pwait",
	288: "accept4", 290: "eventfd2", 291: "epoll_create1", 318: "getrandom",
}

// asm-generic 表（arm64 / riscv64 等使用），仅收录确信的常见项。
var generic = map[uint32]string{
	17: "getcwd", 19: "epoll_create1", 20: "epoll_ctl", 21: "epoll_pwait",
	22: "dup", 23: "dup3", 24: "fcntl", 29: "ioctl", 46: "ftruncate",
	48: "faccessat", 56: "openat", 57: "close", 61: "getdents64", 62: "lseek",
	63: "read", 64: "write", 65: "readv", 66: "writev", 67: "pread64",
	68: "pwrite64", 72: "pselect6", 73: "ppoll", 78: "readlinkat",
	79: "newfstatat", 82: "fsync", 83: "fdatasync", 93: "exit", 98: "futex",
	101: "nanosleep", 113: "clock_gettime", 115: "clock_nanosleep",
	124: "sched_yield", 129: "kill", 134: "rt_sigaction", 135: "rt_sigprocmask",
	172: "getpid", 173: "getppid", 178: "gettid", 198: "socket", 203: "connect",
	206: "sendto", 207: "recvfrom", 211: "sendmsg", 212: "recvmsg", 214: "brk",
	215: "munmap", 222: "mmap", 226: "mprotect", 233: "madvise", 260: "wait4",
	278: "getrandom",
}

var waitingNames = map[string]bool{
	"clock_nanosleep": true,
	"epoll_pwait":     true,
	"epoll_pwait2":    true,
	"epoll_wait":      true,
	"futex":           true,
	"futex_waitv":     true,
	"nanosleep":       true,
	"pause":           true,
	"poll":            true,
	"ppoll":           true,
	"pselect6":        true,
	"rt_sigsuspend":   true,
	"select":          true,
	"wait4":           true,
	"waitid":          true,
}

// Name 返回当前架构下 syscall 号对应的名称，未知则回退 "syscall_<nr>"。
func Name(nr uint32) string {
	var t map[uint32]string
	switch runtime.GOARCH {
	case "amd64", "386":
		t = amd64
	default: // arm64 / riscv64 等使用 asm-generic
		t = generic
	}
	if name, ok := t[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// IsWaitingName 判断 syscall 是否主要表达“等待事件/超时/唤醒”语义。
// 这些调用 wall time 长通常是正常阻塞，不应仅因累计耗时高被报为热点。
func IsWaitingName(name string) bool {
	return waitingNames[name]
}
