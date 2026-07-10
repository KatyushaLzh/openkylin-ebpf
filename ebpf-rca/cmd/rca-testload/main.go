// Command rca-testload provides deterministic local workloads for E2E tests.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	case "mem-pressure":
		err = runMemPressure(os.Args[2:])
	case "mem-pressure-worker":
		err = runMemPressureWorker(os.Args[2:])
	case "normal-mem":
		err = runNormalMem(os.Args[2:])
	case "epoll-wait":
		err = runEpollWait(os.Args[2:])
	case "io-sleep":
		err = runIOSleep(os.Args[2:])
	case "seq-direct-io":
		err = runSequentialDirectIO(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: rca-testload cpu|syscall|lock|mem-pressure|normal-mem|epoll-wait|io-sleep|seq-direct-io --duration 10s")
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
	rate := fs.Int("rate", 30000, "target read syscalls per second (0 = unbounded)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 || *rate < 0 {
		return fmt.Errorf("--duration must be positive and --rate non-negative")
	}
	runtime.LockOSThread()
	_ = setComm("rca_sys_hot")
	fd, err := unix.Open("/dev/zero", unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	buf := []byte{0}
	started := time.Now()
	deadline := started.Add(*dur)
	const batch = 256
	var calls int64
	for time.Now().Before(deadline) {
		for i := 0; i < batch && time.Now().Before(deadline); i++ {
			if _, err := unix.Read(fd, buf); err != nil && err != unix.EINTR {
				return err
			}
			calls++
		}
		if *rate > 0 {
			expected := started.Add(time.Duration(calls) * time.Second / time.Duration(*rate))
			if sleep := time.Until(expected); sleep > 0 {
				time.Sleep(sleep)
			}
		}
	}
	elapsed := time.Since(started).Seconds()
	achieved := float64(calls) / elapsed
	minimumRate := minimumAcceptableSyscallRate(*rate)
	fmt.Printf("syscall_calls=%d elapsed_seconds=%.6f achieved_calls_per_sec=%.2f target_rate=%d\n",
		calls, elapsed, achieved, *rate)
	if achieved < minimumRate {
		return fmt.Errorf("syscall workload achieved %.2f calls/s, require at least %.2f", achieved, minimumRate)
	}
	return nil
}

func minimumAcceptableSyscallRate(target int) float64 {
	minimum := 10000.0
	if paced := float64(target) * 0.8; paced > minimum {
		minimum = paced
	}
	return minimum
}

func runLock(args []string) error {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	threads := fs.Int("threads", 8, "contending OS-thread count")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 {
		return fmt.Errorf("--duration must be positive")
	}
	if *threads < 2 {
		*threads = 2
	}
	runtime.GOMAXPROCS(*threads)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = setComm("rca_lock_hold")
	deadline := time.Now().Add(*dur)
	mu := &futexMutex{}
	var waiters sync.WaitGroup
	var ready sync.WaitGroup
	waiterErrors := make(chan error, *threads-1)
	waiterTIDs := make([]int, *threads-1)
	if err := mu.lock(); err != nil {
		return err
	}
	fmt.Printf("lock_address=0x%x waiter_threads=%d\n",
		uintptr(unsafe.Pointer(&mu.state)), *threads-1)
	for i := 1; i < *threads; i++ {
		waiters.Add(1)
		ready.Add(1)
		go func(index int) {
			defer waiters.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			_ = setComm("rca_lock_wait")
			waiterTIDs[index] = unix.Gettid()
			ready.Done()
			for time.Now().Before(deadline) {
				if err := mu.lock(); err != nil {
					waiterErrors <- fmt.Errorf("waiter tid %d lock: %w", waiterTIDs[index], err)
					return
				}
				time.Sleep(time.Millisecond)
				if err := mu.unlock(); err != nil {
					waiterErrors <- fmt.Errorf("waiter tid %d unlock: %w", waiterTIDs[index], err)
					return
				}
				runtime.Gosched()
			}
		}(i - 1)
	}
	// Every waiter is pinned to an OS thread and enters FUTEX_WAIT_PRIVATE on
	// this exact word. Unlike sync.Mutex, this does not park only the goroutine
	// inside the Go runtime, so do_futex sees the workload lock instance itself.
	ready.Wait()
	waitDeadline := time.Now().Add(500 * time.Millisecond)
	for atomic.LoadUint64(&mu.waitCalls) < uint64(*threads-1) && time.Now().Before(waitDeadline) {
		time.Sleep(time.Millisecond)
	}
	if atomic.LoadUint64(&mu.waitCalls) < 2 {
		_ = mu.unlock()
		waiters.Wait()
		return fmt.Errorf("futex workload established only %d waits", atomic.LoadUint64(&mu.waitCalls))
	}
	if err := mu.unlock(); err != nil {
		return err
	}
	for time.Now().Before(deadline) {
		if err := mu.lock(); err != nil {
			return err
		}
		time.Sleep(20 * time.Millisecond)
		if err := mu.unlock(); err != nil {
			return err
		}
		time.Sleep(time.Millisecond)
	}
	waiters.Wait()
	close(waiterErrors)
	for err := range waiterErrors {
		return err
	}
	tidStrings := make([]string, 0, len(waiterTIDs))
	seenTIDs := make(map[int]struct{}, len(waiterTIDs))
	for _, tid := range waiterTIDs {
		if tid <= 0 {
			continue
		}
		seenTIDs[tid] = struct{}{}
		tidStrings = append(tidStrings, strconv.Itoa(tid))
	}
	fmt.Printf("lock_waiter_tids=%s\n", strings.Join(tidStrings, ","))
	fmt.Printf("lock_acquisitions=%d futex_wait_calls=%d futex_wake_calls=%d distinct_waiter_tids=%d\n",
		atomic.LoadUint64(&mu.acquisitions), atomic.LoadUint64(&mu.waitCalls),
		atomic.LoadUint64(&mu.wakeCalls), len(seenTIDs))
	if len(seenTIDs) < 2 {
		return fmt.Errorf("futex workload observed only %d distinct waiter tids", len(seenTIDs))
	}
	return nil
}

const (
	futexWaitPrivate = 128 // FUTEX_WAIT | FUTEX_PRIVATE_FLAG
	futexWakePrivate = 129 // FUTEX_WAKE | FUTEX_PRIVATE_FLAG
)

// futexMutex is a standard three-state futex lock: 0 is unlocked, 1 is locked
// without a known waiter, and 2 is locked/contended. The state word is also the
// independent lock-address oracle printed by runLock.
type futexMutex struct {
	state        uint32
	acquisitions uint64
	waitCalls    uint64
	wakeCalls    uint64
}

func (m *futexMutex) lock() error {
	if atomic.CompareAndSwapUint32(&m.state, 0, 1) {
		atomic.AddUint64(&m.acquisitions, 1)
		return nil
	}
	for {
		if atomic.SwapUint32(&m.state, 2) == 0 {
			atomic.AddUint64(&m.acquisitions, 1)
			return nil
		}
		atomic.AddUint64(&m.waitCalls, 1)
		_, _, errno := unix.Syscall6(unix.SYS_FUTEX,
			uintptr(unsafe.Pointer(&m.state)), futexWaitPrivate, 2, 0, 0, 0)
		if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR {
			return fmt.Errorf("futex wait: %w", errno)
		}
	}
}

func (m *futexMutex) unlock() error {
	previous := atomic.SwapUint32(&m.state, 0)
	if previous == 0 {
		return fmt.Errorf("unlock of unlocked futex mutex")
	}
	if previous != 2 {
		return nil
	}
	atomic.AddUint64(&m.wakeCalls, 1)
	_, _, errno := unix.Syscall6(unix.SYS_FUTEX,
		uintptr(unsafe.Pointer(&m.state)), futexWakePrivate, 1, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("futex wake: %w", errno)
	}
	return nil
}

// runMemPressure splits page faults across process TGIDs. Each worker remains
// below the CPU-hot threshold; after MemAvailable crosses 15%, worker zero
// alone continues at >=64 MiB/s to provide an unambiguous culprit oracle.
func runMemPressure(args []string) error {
	fs := flag.NewFlagSet("mem-pressure", flag.ContinueOnError)
	dur := fs.Duration("duration", 30*time.Second, "run duration")
	targetAvailable := fs.Int("target-available-pct", 10, "stop allocation at this MemAvailable percentage")
	workers := fs.Int("workers", 8, "faulting child process count")
	fastRate := fs.Int64("fast-rate-mib", 128, "per-worker fault rate before pressure threshold")
	pressureRate := fs.Int64("pressure-rate-mib", 96, "worker-zero fault rate below 15% MemAvailable")
	maxBytes := fs.Int64("max-bytes", 0, "optional allocation cap (0 derives from MemAvailable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 || *targetAvailable < 1 || *targetAvailable >= 15 || *workers < 1 || *workers > 64 ||
		*fastRate <= 0 || *pressureRate < 64 || *maxBytes < 0 {
		return fmt.Errorf("invalid mem-pressure duration/percentage/rate/cap")
	}
	total, available, err := readMemInfoBytes()
	if err != nil {
		return err
	}
	targetAvailableBytes := total * uint64(*targetAvailable) / 100
	var allocation uint64
	if available > targetAvailableBytes {
		allocation = available - targetAvailableBytes
	}
	if *maxBytes > 0 && allocation > uint64(*maxBytes) {
		allocation = uint64(*maxBytes)
	}
	if allocation == 0 || allocation > uint64(^uint(0)>>1) {
		return fmt.Errorf("derived allocation size %d is invalid", allocation)
	}
	pressureThresholdBytes := total * 15 / 100
	var prePressureBytes uint64
	if available > pressureThresholdBytes {
		prePressureBytes = available - pressureThresholdBytes
	}
	if allocation <= prePressureBytes {
		return fmt.Errorf("allocation cap %d cannot cross MemAvailable below 15%%; need more than %d bytes", allocation, prePressureBytes)
	}
	pressureReserve := allocation - prePressureBytes
	minimumReserve := uint64(*pressureRate) * (1 << 20) * memPressureRequiredSustainSeconds
	if pressureReserve < minimumReserve {
		return fmt.Errorf("pressure reserve %d cannot sustain %d MiB/s for %ds", pressureReserve, *pressureRate, memPressureRequiredSustainSeconds)
	}
	plan, err := planMemPressure(prePressureBytes, *dur, *workers, *fastRate)
	if err != nil {
		return err
	}
	fmt.Printf("mem_pressure_plan allocation_bytes=%d pre_pressure_bytes=%d pressure_reserve_bytes=%d requested_workers=%d effective_workers=%d fast_rate_mib_per_worker=%d pressure_rate_mib=%d target_available_pct=%d required_sustain_seconds=%d\n",
		allocation, prePressureBytes, pressureReserve, *workers, plan.Workers, plan.FastRateMiB,
		*pressureRate, *targetAvailable, memPressureRequiredSustainSeconds)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	workerAllocations := splitMemPressureAllocation(prePressureBytes, pressureReserve, plan.Workers)
	children := make([]*exec.Cmd, 0, plan.Workers)
	for index, workerBytes := range workerAllocations {
		if workerBytes == 0 {
			continue
		}
		cmd := exec.Command(exe, "mem-pressure-worker",
			"--duration", dur.String(),
			"--bytes", strconv.FormatUint(workerBytes, 10),
			"--index", strconv.Itoa(index),
			"--fast-rate-mib", strconv.FormatInt(plan.FastRateMiB, 10),
			"--pressure-rate-mib", strconv.FormatInt(*pressureRate, 10),
		)
		if index == 0 {
			cmd.Args = append(cmd.Args,
				"--require-pressure=true",
				"--min-pressure-seconds", strconv.Itoa(memPressureRequiredSustainSeconds),
			)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			for _, child := range children {
				_ = child.Process.Kill()
			}
			return fmt.Errorf("start memory worker %d: %w", index, err)
		}
		children = append(children, cmd)
	}
	var firstErr error
	for _, child := range children {
		if err := child.Wait(); err != nil {
			if memoryWorkerWasOOMKilled(err) {
				fmt.Printf("mem_pressure_oom_victim_pid=%d signal=SIGKILL\n", child.Process.Pid)
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

const (
	memPressurePlanningTailSeconds    = 6
	memPressureRequiredSustainSeconds = 5
	memPressureMaxWorkers             = 64
	memPressureMaxFastRateMiB         = 160
)

type memPressurePlan struct {
	Workers     int
	FastRateMiB int64
}

func planMemPressure(prePressureBytes uint64, duration time.Duration, requestedWorkers int, preferredRateMiB int64) (memPressurePlan, error) {
	if requestedWorkers < 1 || requestedWorkers > memPressureMaxWorkers || preferredRateMiB <= 0 {
		return memPressurePlan{}, fmt.Errorf("invalid memory pressure worker/rate request")
	}
	budgetSeconds := int64(duration/time.Second) - memPressurePlanningTailSeconds
	if budgetSeconds < 1 {
		return memPressurePlan{}, fmt.Errorf("memory pressure duration must exceed %ds", memPressurePlanningTailSeconds)
	}
	requiredAggregateRateMiB := int64(0)
	if prePressureBytes > 0 {
		prePressureMiB := (prePressureBytes + (1 << 20) - 1) / (1 << 20)
		requiredAggregateRateMiB = int64((prePressureMiB + uint64(budgetSeconds) - 1) / uint64(budgetSeconds))
	}
	requiredWorkers := requestedWorkers
	if requiredAggregateRateMiB > 0 {
		workersAtPreferredRate := int((requiredAggregateRateMiB + preferredRateMiB - 1) / preferredRateMiB)
		if workersAtPreferredRate > requiredWorkers {
			requiredWorkers = workersAtPreferredRate
		}
	}
	if requiredWorkers > memPressureMaxWorkers {
		requiredWorkers = memPressureMaxWorkers
	}
	effectiveRate := preferredRateMiB
	if requiredAggregateRateMiB > 0 {
		perWorker := (requiredAggregateRateMiB + int64(requiredWorkers) - 1) / int64(requiredWorkers)
		if perWorker > effectiveRate {
			effectiveRate = perWorker
		}
	}
	if effectiveRate > memPressureMaxFastRateMiB {
		return memPressurePlan{}, fmt.Errorf("need %d workers at %d MiB/s each to reach pressure safely; per-worker cap is %d MiB/s",
			requiredWorkers, effectiveRate, memPressureMaxFastRateMiB)
	}
	return memPressurePlan{Workers: requiredWorkers, FastRateMiB: effectiveRate}, nil
}

func memoryWorkerWasOOMKilled(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func splitMemPressureAllocation(prePressureBytes, pressureReserve uint64, workers int) []uint64 {
	allocations := make([]uint64, workers)
	base := prePressureBytes / uint64(workers)
	remainder := prePressureBytes % uint64(workers)
	for index := range allocations {
		allocations[index] = base
		if uint64(index) < remainder {
			allocations[index]++
		}
	}
	allocations[0] += pressureReserve
	return allocations
}

func runMemPressureWorker(args []string) error {
	fs := flag.NewFlagSet("mem-pressure-worker", flag.ContinueOnError)
	dur := fs.Duration("duration", 30*time.Second, "run duration")
	bytes := fs.Uint64("bytes", 0, "anonymous bytes assigned to this worker")
	index := fs.Int("index", 0, "worker index; only zero grows below 15% MemAvailable")
	fastRate := fs.Int64("fast-rate-mib", 128, "fault rate before pressure threshold")
	pressureRate := fs.Int64("pressure-rate-mib", 96, "worker-zero rate below pressure threshold")
	requirePressure := fs.Bool("require-pressure", false, "fail unless this worker faults below 15% MemAvailable for the required interval")
	minPressureSeconds := fs.Int("min-pressure-seconds", memPressureRequiredSustainSeconds, "required below-15% faulting interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 || *bytes == 0 || *bytes > uint64(^uint(0)>>1) || *index < 0 ||
		*fastRate <= 0 || *pressureRate < 64 || *minPressureSeconds < 1 {
		return fmt.Errorf("invalid mem-pressure-worker arguments")
	}
	region, err := unix.Mmap(-1, 0, int(*bytes), unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("mmap %d bytes: %w", *bytes, err)
	}
	defer unix.Munmap(region)
	_ = unix.Madvise(region, unix.MADV_NOHUGEPAGE)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = setComm("rca_mem_pressure")
	deadline := time.Now().Add(*dur)
	started := time.Now()
	pageSize := unix.Getpagesize()
	const batchBytes = 4 << 20
	minAvailablePct := 100.0
	var pressureFaultStart time.Time
	var pressureFaultEnd time.Time
	touchedBytes := 0
	for touched := 0; touched < len(region) && time.Now().Before(deadline); {
		batchEnd := touched + batchBytes
		if batchEnd > len(region) {
			batchEnd = len(region)
		}
		batchStarted := time.Now()
		for offset := touched; offset < batchEnd; offset += pageSize {
			region[offset] = byte(offset/pageSize + 1)
		}
		if batchEnd == len(region) {
			region[len(region)-1] ^= 1
		}
		currentTotal, currentAvailable, readErr := readMemInfoBytes()
		if readErr != nil {
			return readErr
		}
		rateMiB := *fastRate
		availablePct := float64(currentAvailable) / float64(currentTotal) * 100
		if availablePct < minAvailablePct {
			minAvailablePct = availablePct
		}
		if currentAvailable*100 < currentTotal*15 {
			if *index != 0 {
				break
			}
			if pressureFaultStart.IsZero() {
				pressureFaultStart = time.Now()
				fmt.Printf("mem_pressure_crossed worker_index=%d available_pct=%.4f elapsed_ms=%d\n",
					*index, availablePct, time.Since(started).Milliseconds())
			}
			rateMiB = *pressureRate
		}
		minimum := time.Duration(int64(batchEnd-touched)) * time.Second /
			time.Duration(rateMiB*(1<<20))
		if sleep := minimum - time.Since(batchStarted); sleep > 0 {
			time.Sleep(sleep)
		}
		// A paced batch represents fault activity spread over its complete rate
		// interval. Closing the interval before the pacing sleep would
		// under-count the final batch by up to 4 MiB/rate and reject a reserve
		// sized for exactly the required sustained window.
		if currentAvailable*100 < currentTotal*15 && *index == 0 {
			pressureFaultEnd = time.Now()
		}
		touched = batchEnd
		touchedBytes = touched
	}
	pressureFaultSeconds := 0.0
	if !pressureFaultStart.IsZero() && !pressureFaultEnd.Before(pressureFaultStart) {
		pressureFaultSeconds = pressureFaultEnd.Sub(pressureFaultStart).Seconds()
	}
	if *index == 0 {
		fmt.Printf("mem_pressure_result worker_index=0 crossed_pressure=%t min_available_pct=%.4f pressure_fault_seconds=%.3f touched_bytes=%d\n",
			!pressureFaultStart.IsZero(), minAvailablePct, pressureFaultSeconds, touchedBytes)
	}
	if *requirePressure && (pressureFaultStart.IsZero() || pressureFaultSeconds < float64(*minPressureSeconds)) {
		return fmt.Errorf("memory pressure worker did not fault below 15%% for %ds: crossed=%t duration=%.3fs min_available=%.4f%%",
			*minPressureSeconds, !pressureFaultStart.IsZero(), pressureFaultSeconds, minAvailablePct)
	}
	if remaining := time.Until(deadline); remaining > 0 {
		time.Sleep(remaining)
	}
	runtime.KeepAlive(region)
	return nil
}

func readMemInfoBytes() (total, available uint64, err error) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		var value uint64
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			if _, err := fmt.Sscanf(line, "MemTotal: %d kB", &value); err == nil {
				total = value * 1024
			}
		case strings.HasPrefix(line, "MemAvailable:"):
			if _, err := fmt.Sscanf(line, "MemAvailable: %d kB", &value); err == nil {
				available = value * 1024
			}
		}
	}
	if total == 0 || available == 0 {
		return 0, 0, fmt.Errorf("MemTotal/MemAvailable unavailable")
	}
	return total, available, nil
}

// runNormalMem allocates and faults in a sizeable anonymous resident set once,
// then keeps it alive without repeatedly churning pages.  It exercises process
// contribution metrics without creating sustained system memory pressure.
func runNormalMem(args []string) error {
	fs := flag.NewFlagSet("normal-mem", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	bytes := fs.Int64("bytes", 128<<20, "anonymous bytes to allocate and fault in")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 {
		return fmt.Errorf("--duration must be positive")
	}
	if *bytes <= 0 || uint64(*bytes) > uint64(^uint(0)>>1) {
		return fmt.Errorf("--bytes must be a positive value representable as int")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = setComm("rca_mem_normal")
	deadline := time.Now().Add(*dur)
	resident := make([]byte, int(*bytes))
	pageSize := unix.Getpagesize()
	for offset := 0; offset < len(resident); offset += pageSize {
		resident[offset] = byte(offset/pageSize + 1)
	}
	resident[len(resident)-1] ^= 1
	if remaining := time.Until(deadline); remaining > 0 {
		time.Sleep(remaining)
	}
	runtime.KeepAlive(resident)
	return nil
}

// runEpollWait performs one long, empty epoll wait (restarting only after a
// signal).  Long wall time at a low call rate is normal event-loop behaviour.
func runEpollWait(args []string) error {
	fs := flag.NewFlagSet("epoll-wait", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 {
		return fmt.Errorf("--duration must be positive")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = setComm("rca_epoll_wait")
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("create epoll fd: %w", err)
	}
	defer unix.Close(epfd)

	deadline := time.Now().Add(*dur)
	events := make([]unix.EpollEvent, 1)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		timeoutMS := int((remaining + time.Millisecond - 1) / time.Millisecond)
		n, err := unix.EpollWait(epfd, events, timeoutMS)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("epoll wait: %w", err)
		}
		if n != 0 {
			return fmt.Errorf("empty epoll set unexpectedly returned %d event(s)", n)
		}
	}
}

// runIOSleep models an ordinary blocking read: a pipe reader sleeps until a
// low-rate producer writes one byte.  This is file-descriptor I/O wait, not
// futex or kernel-lock contention.
func runIOSleep(args []string) error {
	fs := flag.NewFlagSet("io-sleep", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	interval := fs.Duration("interval", 250*time.Millisecond, "producer interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 {
		return fmt.Errorf("--duration must be positive")
	}
	if *interval <= 0 {
		return fmt.Errorf("--interval must be positive")
	}

	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC); err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}
	readFD, writeFD := pipeFDs[0], pipeFDs[1]
	defer unix.Close(readFD)
	deadline := time.Now().Add(*dur)
	writerDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_ = setComm("rca_io_wake")
		defer unix.Close(writeFD)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				writerDone <- nil
				return
			}
			pause := *interval
			if pause > remaining {
				pause = remaining
			}
			time.Sleep(pause)
			if time.Now().Before(deadline) {
				if _, err := unix.Write(writeFD, []byte{1}); err != nil {
					writerDone <- fmt.Errorf("write pipe: %w", err)
					return
				}
			}
		}
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = setComm("rca_io_sleep")
	buf := []byte{0}
	for {
		n, err := unix.Read(readFD, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("read pipe: %w", err)
		}
		if n == 0 {
			break
		}
	}
	return <-writerDone
}

// runSequentialDirectIO issues paced, queue-depth-one sequential O_DIRECT
// writes.  Pacing keeps syscall rate and CPU use low while still exercising
// the block collector with real, shallow-queue I/O.
func runSequentialDirectIO(args []string) error {
	fs := flag.NewFlagSet("seq-direct-io", flag.ContinueOnError)
	dur := fs.Duration("duration", 10*time.Second, "run duration")
	path := fs.String("path", "", "direct-I/O file path")
	fileSize := fs.Int64("size", 64<<20, "file size in bytes")
	blockSize := fs.Int("block-size", 128<<10, "I/O size in bytes")
	alignment := fs.Int("alignment", 4096, "buffer and offset alignment")
	interval := fs.Duration("interval", 10*time.Millisecond, "minimum interval between writes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dur <= 0 {
		return fmt.Errorf("--duration must be positive")
	}
	if *path == "" {
		return fmt.Errorf("--path is required")
	}
	if *fileSize <= 0 || *blockSize <= 0 || *alignment <= 0 {
		return fmt.Errorf("--size, --block-size and --alignment must be positive")
	}
	if *blockSize%*alignment != 0 || *fileSize%int64(*blockSize) != 0 {
		return fmt.Errorf("--block-size must be alignment-sized and --size must be a block-size multiple")
	}
	if *interval < 0 {
		return fmt.Errorf("--interval cannot be negative")
	}

	buf, err := alignedBuffer(*blockSize, *alignment)
	if err != nil {
		return err
	}
	for i := range buf {
		buf[i] = byte((i*131 + 17) & 0xff)
	}
	fd, err := unix.Open(*path, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_DIRECT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open direct-I/O file: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, *fileSize); err != nil {
		return fmt.Errorf("size direct-I/O file: %w", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_ = setComm("rca_seq_direct")
	deadline := time.Now().Add(*dur)
	var offset int64
	for time.Now().Before(deadline) {
		started := time.Now()
		n, err := unix.Pwrite(fd, buf, offset)
		if err != nil {
			return fmt.Errorf("direct pwrite at offset %d: %w", offset, err)
		}
		if n != len(buf) {
			return fmt.Errorf("short direct pwrite at offset %d: wrote %d of %d", offset, n, len(buf))
		}
		offset += int64(len(buf))
		if offset >= *fileSize {
			offset = 0
		}
		if remaining := *interval - time.Since(started); remaining > 0 {
			time.Sleep(remaining)
		}
	}
	return nil
}

func alignedBuffer(size, alignment int) ([]byte, error) {
	if size <= 0 || alignment <= 0 {
		return nil, fmt.Errorf("buffer size and alignment must be positive")
	}
	if size > int(^uint(0)>>1)-(alignment-1) {
		return nil, fmt.Errorf("aligned buffer size overflows int")
	}
	storage := make([]byte, size+alignment-1)
	base := uintptr(unsafe.Pointer(&storage[0]))
	offset := int((uintptr(alignment) - base%uintptr(alignment)) % uintptr(alignment))
	return storage[offset : offset+size], nil
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
