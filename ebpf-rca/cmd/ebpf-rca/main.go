// Command ebpf-rca：基于 eBPF 的系统异常观测与根因定位工具。
//
// 场景：
//
//	--scenario cpu      CPU 异常占用 / 调度延迟
//	--scenario io       I/O 延迟抖动 / 阻塞等待（块层时延 + 队列深度）
//	--scenario mem      内存抖动 / OOM 风险（direct reclaim + kswapd + 缺页）
//	--scenario lock     锁竞争（off-CPU 阻塞 + 唤醒链）
//	--scenario syscall  系统调用热点（高频/高耗时，raw_syscalls 直方）
//	--scenario all      同时运行全部场景
//
// 加 --report <file> 时，结果汇总为一份 Markdown 诊断报告（而非逐条流式输出）。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
	"github.com/os2026/ebpf-rca/internal/detector"
	"github.com/os2026/ebpf-rca/internal/output"
	"github.com/os2026/ebpf-rca/internal/rca"
	"github.com/os2026/ebpf-rca/internal/report"
	"github.com/os2026/ebpf-rca/internal/schema"
)

type config struct {
	interval  time.Duration
	threshold thresholds
	sustain   int
	duration  time.Duration
	format    string
	targetPID uint32
}

type thresholds struct {
	CPU                float64
	IOP99Ms            float64
	MemAvailFloorPct   float64
	LockOffcpuRatio    float64
	SyscallCallsPerSec float64
}

var defaultThresholds = thresholds{
	CPU:                0.90,
	IOP99Ms:            20,
	MemAvailFloorPct:   15,
	LockOffcpuRatio:    0.30,
	SyscallCallsPerSec: 10000,
}

// handler 处理一条诊断结果（流式输出或汇总）。
type handler func(schema.AnomalyReport)

func main() {
	scenario := flag.String("scenario", "cpu", "异常场景：cpu|io|mem|lock|syscall|all")
	interval := flag.Duration("interval", time.Second, "采样窗口")
	threshold := flag.Float64("threshold", 0, "判定阈值（cpu:0.90；io:P99毫秒20；mem:可用占比下限15；lock:0.30；syscall:次/秒10000）")
	cpuThreshold := flag.Float64("cpu-threshold", defaultThresholds.CPU, "CPU 单核占用阈值")
	ioP99Threshold := flag.Float64("io-p99-threshold-ms", defaultThresholds.IOP99Ms, "I/O P99 时延阈值(毫秒)")
	memAvailFloor := flag.Float64("mem-avail-floor-pct", defaultThresholds.MemAvailFloorPct, "内存可用占比下限(%)")
	lockOffcpuThreshold := flag.Float64("lock-offcpu-threshold", defaultThresholds.LockOffcpuRatio, "锁/阻塞 off-CPU 占比阈值")
	syscallRateThreshold := flag.Float64("syscall-rate-threshold", defaultThresholds.SyscallCallsPerSec, "系统调用频率阈值(次/秒)")
	targetPID := flag.Uint("target-pid", 0, "仅 syscall 场景：只观测指定进程 pid/tgid（0=全局）")
	sustain := flag.Int("sustain", 3, "连续超过阈值多少个窗口才触发")
	duration := flag.Duration("duration", 0, "总运行时长（0 = 直到 Ctrl-C）")
	format := flag.String("format", "json", "流式输出格式：json|yaml|md")
	outPath := flag.String("output", "", "流式输出文件（默认标准输出）")
	reportPath := flag.String("report", "", "汇总诊断报告输出文件(Markdown)；设置后不再流式输出")
	flag.Parse()

	visited := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	th, err := buildThresholds(*scenario, *threshold, visited["threshold"], thresholds{
		CPU:                *cpuThreshold,
		IOP99Ms:            *ioP99Threshold,
		MemAvailFloorPct:   *memAvailFloor,
		LockOffcpuRatio:    *lockOffcpuThreshold,
		SyscallCallsPerSec: *syscallRateThreshold,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(2)
	}
	if *interval <= 0 {
		fmt.Fprintln(os.Stderr, "配置错误: --interval 必须大于 0")
		os.Exit(2)
	}
	if *targetPID > uint(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "配置错误: --target-pid 超出 uint32 范围")
		os.Exit(2)
	}

	out := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open output:", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	cfg := config{
		interval:  *interval,
		threshold: th,
		sustain:   *sustain,
		duration:  *duration,
		format:    *format,
		targetPID: uint32(*targetPID),
	}

	// 结果处理：报告模式聚合，否则流式输出。
	agg := report.New()
	var h handler
	if *reportPath != "" {
		h = func(r schema.AnomalyReport) { agg.Add(r) }
	} else {
		h = func(r schema.AnomalyReport) {
			if err := output.Write(out, r, cfg.format); err != nil {
				fmt.Fprintln(os.Stderr, "output:", err)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	var runErr error
	switch *scenario {
	case "cpu":
		runErr = runCPU(ctx, cfg, h)
	case "io":
		runErr = runIO(ctx, cfg, h)
	case "mem":
		runErr = runMem(ctx, cfg, h)
	case "lock":
		runErr = runLock(ctx, cfg, h)
	case "syscall":
		runErr = runSyscall(ctx, cfg, h)
	case "all":
		runErr = runAll(ctx, cfg, h)
	default:
		fmt.Fprintf(os.Stderr, "未知场景：%s（支持 cpu|io|mem|lock|syscall|all）\n", *scenario)
		os.Exit(2)
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "error:", runErr)
		fmt.Fprintln(os.Stderr, "提示：需要 root 或 CAP_BPF/CAP_PERFMON 权限，内核需启用 BTF。")
		os.Exit(1)
	}

	if *reportPath != "" {
		f, ferr := os.Create(*reportPath)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "open report:", ferr)
			os.Exit(1)
		}
		defer f.Close()
		if rerr := agg.Render(f, time.Since(start)); rerr != nil {
			fmt.Fprintln(os.Stderr, "render report:", rerr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[ebpf-rca] 诊断报告已写入 %s（%d 项）\n", *reportPath, agg.Count())
	}
}

func buildThresholds(scenario string, legacy float64, legacySet bool, th thresholds) (thresholds, error) {
	if legacySet && scenario == "all" {
		return th, fmt.Errorf("--threshold 在 --scenario all 下语义不明确，请使用各场景专用阈值参数")
	}
	if !legacySet {
		return th, nil
	}
	switch scenario {
	case "cpu":
		th.CPU = legacy
	case "io":
		th.IOP99Ms = legacy
	case "mem":
		th.MemAvailFloorPct = legacy
	case "lock":
		th.LockOffcpuRatio = legacy
	case "syscall":
		th.SyscallCallsPerSec = legacy
	}
	return th, nil
}

// loopTimers 构造采样 ticker 与可选的运行时长 deadline。
func loopTimers(cfg config) (*time.Ticker, <-chan time.Time, func()) {
	ticker := time.NewTicker(cfg.interval)
	var deadline <-chan time.Time
	var timer *time.Timer
	if cfg.duration > 0 {
		timer = time.NewTimer(cfg.duration)
		deadline = timer.C
	}
	cancel := func() {
		ticker.Stop()
		if timer != nil {
			timer.Stop()
		}
	}
	return ticker, deadline, cancel
}

// runLoop 驱动统一的采样循环，每个窗口调用 tick(now)。
func runLoop(ctx context.Context, cfg config, tick func(time.Time)) {
	ticker, deadline, cancel := loopTimers(cfg)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case now := <-ticker.C:
			tick(now)
		}
	}
}

func runCPU(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewCPUCollector()
	if err != nil {
		return err
	}
	defer col.Close()
	det := detector.NewCPUDetector(cfg.threshold.CPU, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=cpu interval=%s threshold=%.2f sustain=%d\n",
		cfg.interval, cfg.threshold.CPU, cfg.sustain)
	_, _ = col.Poll(cfg.interval)
	runLoop(ctx, cfg, func(now time.Time) {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			return
		}
		for _, sig := range det.Detect(samples, now) {
			h(rca.BuildCPUReport(sig, cfg.threshold.CPU))
		}
	})
	return nil
}

func runIO(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewIOCollector()
	if err != nil {
		return err
	}
	defer col.Close()
	det := detector.NewIODetector(cfg.threshold.IOP99Ms, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=io interval=%s p99_threshold=%.1fms sustain=%d\n",
		cfg.interval, cfg.threshold.IOP99Ms, cfg.sustain)
	_, _ = col.Poll(cfg.interval)
	runLoop(ctx, cfg, func(now time.Time) {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			return
		}
		for _, sig := range det.Detect(samples, now) {
			h(rca.BuildIOReport(sig, cfg.threshold.IOP99Ms))
		}
	})
	return nil
}

func runMem(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewMemCollector()
	if err != nil {
		return err
	}
	defer col.Close()
	det := detector.NewMemDetector(cfg.threshold.MemAvailFloorPct, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=mem interval=%s avail_floor=%.0f%% sustain=%d\n",
		cfg.interval, cfg.threshold.MemAvailFloorPct, cfg.sustain)
	_, _ = col.Poll(cfg.interval)
	runLoop(ctx, cfg, func(now time.Time) {
		snap, err := col.Poll(cfg.interval)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			return
		}
		for _, sig := range det.Detect(snap, now) {
			h(rca.BuildMemReport(sig, cfg.threshold.MemAvailFloorPct))
		}
	})
	return nil
}

func runLock(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewLockCollector()
	if err != nil {
		return err
	}
	defer col.Close()
	det := detector.NewLockDetector(cfg.threshold.LockOffcpuRatio, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=lock interval=%s threshold=%.2f sustain=%d\n",
		cfg.interval, cfg.threshold.LockOffcpuRatio, cfg.sustain)
	_, _ = col.Poll(cfg.interval)
	runLoop(ctx, cfg, func(now time.Time) {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			return
		}
		for _, sig := range det.Detect(samples, now) {
			stack := col.ResolveStack(sig.Sample.StackID, 8)
			h(rca.BuildLockReport(sig, stack, cfg.threshold.LockOffcpuRatio))
		}
	})
	return nil
}

func runSyscall(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewSyscallCollector(cfg.targetPID)
	if err != nil {
		return err
	}
	defer col.Close()
	det := detector.NewSyscallDetector(cfg.threshold.SyscallCallsPerSec, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=syscall interval=%s calls/s_floor=%.0f target_pid=%d sustain=%d\n",
		cfg.interval, cfg.threshold.SyscallCallsPerSec, cfg.targetPID, cfg.sustain)
	_, _ = col.Poll(cfg.interval)
	runLoop(ctx, cfg, func(now time.Time) {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			return
		}
		for _, sig := range det.Detect(samples, now) {
			h(rca.BuildSyscallReport(sig, cfg.threshold.SyscallCallsPerSec, cfg.targetPID))
		}
	})
	return nil
}

// runAll 同时运行全部场景；单个场景初始化失败仅告警并跳过，不影响其余。
func runAll(ctx context.Context, cfg config, h handler) error {
	var ticks []func(now time.Time)
	var closers []func()
	warn := func(name string, err error) {
		fmt.Fprintf(os.Stderr, "[ebpf-rca] 跳过场景 %s：%v\n", name, err)
	}

	if col, err := collector.NewCPUCollector(); err != nil {
		warn("cpu", err)
	} else {
		closers = append(closers, col.Close)
		det := detector.NewCPUDetector(cfg.threshold.CPU, cfg.sustain)
		_, _ = col.Poll(cfg.interval)
		ticks = append(ticks, func(now time.Time) {
			s, e := col.Poll(cfg.interval)
			if e != nil {
				return
			}
			for _, sig := range det.Detect(s, now) {
				h(rca.BuildCPUReport(sig, cfg.threshold.CPU))
			}
		})
	}

	if col, err := collector.NewIOCollector(); err != nil {
		warn("io", err)
	} else {
		closers = append(closers, col.Close)
		det := detector.NewIODetector(cfg.threshold.IOP99Ms, cfg.sustain)
		_, _ = col.Poll(cfg.interval)
		ticks = append(ticks, func(now time.Time) {
			s, e := col.Poll(cfg.interval)
			if e != nil {
				return
			}
			for _, sig := range det.Detect(s, now) {
				h(rca.BuildIOReport(sig, cfg.threshold.IOP99Ms))
			}
		})
	}

	if col, err := collector.NewMemCollector(); err != nil {
		warn("mem", err)
	} else {
		closers = append(closers, col.Close)
		det := detector.NewMemDetector(cfg.threshold.MemAvailFloorPct, cfg.sustain)
		_, _ = col.Poll(cfg.interval)
		ticks = append(ticks, func(now time.Time) {
			snap, e := col.Poll(cfg.interval)
			if e != nil {
				return
			}
			for _, sig := range det.Detect(snap, now) {
				h(rca.BuildMemReport(sig, cfg.threshold.MemAvailFloorPct))
			}
		})
	}

	if col, err := collector.NewLockCollector(); err != nil {
		warn("lock", err)
	} else {
		closers = append(closers, col.Close)
		det := detector.NewLockDetector(cfg.threshold.LockOffcpuRatio, cfg.sustain)
		_, _ = col.Poll(cfg.interval)
		ticks = append(ticks, func(now time.Time) {
			s, e := col.Poll(cfg.interval)
			if e != nil {
				return
			}
			for _, sig := range det.Detect(s, now) {
				stack := col.ResolveStack(sig.Sample.StackID, 8)
				h(rca.BuildLockReport(sig, stack, cfg.threshold.LockOffcpuRatio))
			}
		})
	}

	if col, err := collector.NewSyscallCollector(cfg.targetPID); err != nil {
		warn("syscall", err)
	} else {
		closers = append(closers, col.Close)
		det := detector.NewSyscallDetector(cfg.threshold.SyscallCallsPerSec, cfg.sustain)
		_, _ = col.Poll(cfg.interval)
		ticks = append(ticks, func(now time.Time) {
			s, e := col.Poll(cfg.interval)
			if e != nil {
				return
			}
			for _, sig := range det.Detect(s, now) {
				h(rca.BuildSyscallReport(sig, cfg.threshold.SyscallCallsPerSec, cfg.targetPID))
			}
		})
	}

	for _, c := range closers {
		defer c()
	}
	if len(ticks) == 0 {
		return fmt.Errorf("无任何场景成功初始化")
	}
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=all 已启动 %d 个场景 interval=%s sustain=%d\n",
		len(ticks), cfg.interval, cfg.sustain)
	runLoop(ctx, cfg, func(now time.Time) {
		for _, t := range ticks {
			t(now)
		}
	})
	return nil
}
