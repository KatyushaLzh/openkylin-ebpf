// Command rca-testload provides deterministic local workloads for E2E tests.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "cpu":
		err = runCPU(os.Args[2:])
	case "syscall":
		err = runSyscall(os.Args[2:])
	case "lock":
		err = runLock(os.Args[2:])
	case "lock-worker":
		err = runLockWorker(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: rca-testload cpu|syscall|lock --duration 10s")
}

func runCPU(args []string) error {
	fs := flag.NewFlagSet("cpu", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runtime.LockOSThread()
	_ = setComm("rca_cpu_hot")
	deadline := time.Now().Add(*dur)
	var x uint64 = 1
	for time.Now().Before(deadline) {
		x = x*1103515245 + 12345
		x ^= x >> 17
	}
	if x == 0 {
		fmt.Fprintln(io.Discard, x)
	}
	return nil
}

func runSyscall(args []string) error {
	fs := flag.NewFlagSet("syscall", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	runtime.LockOSThread()
	_ = setComm("rca_sys_hot")
	fd, err := unix.Open("/dev/zero", unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	buf := []byte{0}
	deadline := time.Now().Add(*dur)
	for time.Now().Before(deadline) {
		if _, err := unix.Read(fd, buf); err != nil && err != unix.EINTR {
			return err
		}
	}
	return nil
}

func runLock(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	threads := fs.Int("threads", 8, "worker process count")
	path := fs.String("path", "", "lock file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *threads < 2 {
		*threads = 2
	}
	if *path == "" {
		*path = fmt.Sprintf("%s/rca-testload-lock-%d", os.TempDir(), os.Getpid())
	}
	f, err := os.OpenFile(*path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	_ = f.Close()
	defer os.Remove(*path)

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var procs []*exec.Cmd
	startWorker := func(role string) error {
		cmd := exec.Command(exe, "lock-worker",
			"--role", role,
			"--path", *path,
			"--duration", dur.String(),
		)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			return err
		}
		procs = append(procs, cmd)
		return nil
	}
	if err := startWorker("holder"); err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	for i := 1; i < *threads; i++ {
		if err := startWorker("waiter"); err != nil {
			return err
		}
	}
	var firstErr error
	for _, cmd := range procs {
		if err := cmd.Wait(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func runLockWorker(args []string) error {
	fs := flag.NewFlagSet("lock-worker", flag.ContinueOnError)
	role := fs.String("role", "waiter", "holder|waiter")
	path := fs.String("path", "", "lock file path")
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("--path is required")
	}
	runtime.LockOSThread()
	if *role == "holder" {
		_ = setComm("rca_lock_hold")
	} else {
		_ = setComm("rca_lock_wait")
	}
	fd, err := unix.Open(*path, unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(*dur)
	for time.Now().Before(deadline) {
		if err := unix.Flock(fd, unix.LOCK_EX); err != nil && err != unix.EINTR {
			return err
		}
		if *role == "holder" {
			time.Sleep(50 * time.Millisecond)
		}
		if err := unix.Flock(fd, unix.LOCK_UN); err != nil && err != unix.EINTR {
			return err
		}
		if *role != "holder" {
			time.Sleep(time.Millisecond)
		}
	}
	return nil
}

func setComm(name string) error {
	var buf [16]byte
	copy(buf[:], name)
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
