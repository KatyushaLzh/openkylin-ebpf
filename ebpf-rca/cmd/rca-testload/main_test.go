package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestAlignedBuffer(t *testing.T) {
	buf, err := alignedBuffer(8192, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != 8192 {
		t.Fatalf("len(buf)=%d, want 8192", len(buf))
	}
	if uintptr(unsafe.Pointer(&buf[0]))%4096 != 0 {
		t.Fatal("buffer is not 4096-byte aligned")
	}
}

func TestSplitMemPressureAllocationReservesSustainedCulprit(t *testing.T) {
	got := splitMemPressureAllocation(800, 200, 4)
	want := []uint64{400, 200, 200, 200}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allocation split = %v, want %v", got, want)
	}
}

func TestPlanMemPressureExpandsWorkersBeforeRate(t *testing.T) {
	const mib = uint64(1 << 20)
	plan, err := planMemPressure(24*32*128*mib, 30*time.Second, 8, 128)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Workers != 32 || plan.FastRateMiB != 128 {
		t.Fatalf("plan=%+v, want 32 workers at 128 MiB/s", plan)
	}

	plan, err = planMemPressure(24*64*140*mib, 30*time.Second, 8, 128)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Workers != 64 || plan.FastRateMiB != 140 {
		t.Fatalf("capped plan=%+v, want 64 workers at 140 MiB/s", plan)
	}

	if _, err := planMemPressure(24*64*161*mib, 30*time.Second, 8, 128); err == nil {
		t.Fatal("unsafe per-worker fault rate was accepted")
	}
	if _, err := planMemPressure(mib, 6*time.Second, 8, 128); err == nil {
		t.Fatal("duration without a pressure-sustain tail was accepted")
	}
}

func TestMinimumAcceptableSyscallRate(t *testing.T) {
	if got := minimumAcceptableSyscallRate(30000); got != 24000 {
		t.Fatalf("30k target minimum=%v, want 24k", got)
	}
	if got := minimumAcceptableSyscallRate(0); got != 10000 {
		t.Fatalf("unpaced minimum=%v, want product threshold 10k", got)
	}
}

func TestFutexMutexMakesMultipleThreadsWaitOnOneWord(t *testing.T) {
	mu := &futexMutex{}
	if err := mu.lock(); err != nil {
		t.Fatal(err)
	}
	const waiterCount = 4
	var ready sync.WaitGroup
	var done sync.WaitGroup
	errs := make(chan error, waiterCount)
	ready.Add(waiterCount)
	done.Add(waiterCount)
	for i := 0; i < waiterCount; i++ {
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready.Done()
			if err := mu.lock(); err != nil {
				errs <- err
				return
			}
			if err := mu.unlock(); err != nil {
				errs <- err
			}
		}()
	}
	ready.Wait()
	deadline := time.Now().Add(time.Second)
	for atomic.LoadUint64(&mu.waitCalls) < waiterCount && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := atomic.LoadUint64(&mu.waitCalls); got < waiterCount {
		t.Fatalf("futex wait calls=%d, want at least %d", got, waiterCount)
	}
	if err := mu.unlock(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		done.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("futex waiter chain did not drain")
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := atomic.LoadUint64(&mu.acquisitions); got != waiterCount+1 {
		t.Fatalf("acquisitions=%d, want %d", got, waiterCount+1)
	}
}

func TestNormalNegativeWorkloadsFinish(t *testing.T) {
	t.Run("normal-mem", func(t *testing.T) {
		if err := runNormalMem([]string{"--duration", "5ms", "--bytes", "8192"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("paced-mem-pressure", func(t *testing.T) {
		if err := runMemPressureWorker([]string{
			"--duration", "5ms", "--bytes", "8192", "--index", "0",
			"--fast-rate-mib", "64", "--pressure-rate-mib", "64",
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("epoll-wait", func(t *testing.T) {
		started := time.Now()
		if err := runEpollWait([]string{"--duration", "5ms"}); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) < 4*time.Millisecond {
			t.Fatal("epoll workload returned without waiting")
		}
	})
	t.Run("io-sleep", func(t *testing.T) {
		if err := runIOSleep([]string{"--duration", "15ms", "--interval", "3ms"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSequentialDirectIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct.img")
	err := runSequentialDirectIO([]string{
		"--duration", "5ms",
		"--path", path,
		"--size", "8192",
		"--block-size", "4096",
		"--alignment", "4096",
		"--interval", "0",
	})
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOTSUP) {
		t.Skipf("test filesystem does not support O_DIRECT: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 8192 {
		t.Fatalf("direct-I/O file size=%d, want 8192", info.Size())
	}
}

func TestNegativeWorkloadArgumentsAreStrict(t *testing.T) {
	if err := runNormalMem([]string{"--duration", "0s"}); err == nil {
		t.Fatal("normal-mem accepted zero duration")
	}
	if err := runEpollWait([]string{"--duration", "0s"}); err == nil {
		t.Fatal("epoll-wait accepted zero duration")
	}
	if err := runIOSleep([]string{"--duration", "1s", "--interval", "0s"}); err == nil {
		t.Fatal("io-sleep accepted zero interval")
	}
	if err := runSequentialDirectIO([]string{"--duration", "1s"}); err == nil {
		t.Fatal("seq-direct-io accepted missing path")
	}
}
