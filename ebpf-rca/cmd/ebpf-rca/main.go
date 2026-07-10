// Command ebpf-rca：基于 eBPF 的系统异常观测与根因定位工具。
//
// 场景：
//
//	--scenario cpu      CPU 异常占用 / 调度延迟
//	--scenario io       I/O 延迟抖动 / 阻塞等待（块层时延 + 队列深度）
//	--scenario mem      内存抖动 / OOM 风险（direct reclaim + kswapd + 缺页）
//	--scenario lock     锁竞争（off-CPU 阻塞 + 唤醒链）
//	--scenario syscall  系统调用热点（高频/高耗时，typed sys_enter/sys_exit 直方图）
//	--scenario all      同时运行全部场景
//
// 加 --report <file> 时，结果汇总为一份 Markdown 诊断报告（而非逐条流式输出）。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/output"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/rca"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/report"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

type config struct {
	scenario     string
	interval     time.Duration
	threshold    thresholds
	sustain      int
	duration     time.Duration
	format       string
	targetPID    uint32
	allowPartial bool
	tracker      *collectorTracker
	lock         lockConfig
}

type lockConfig struct {
	includeBlocking bool
	topN            int
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
type handler func(schema.AnomalyReport) error

func main() {
	scenario := flag.String("scenario", "cpu", "异常场景：cpu|io|mem|lock|syscall|all")
	interval := flag.Duration("interval", time.Second, "采样窗口")
	threshold := flag.Float64("threshold", 0, "判定阈值（cpu:0.90；io:P99毫秒20；mem:可用占比下限15；lock:0.30；syscall:次/秒10000）")
	cpuThreshold := flag.Float64("cpu-threshold", defaultThresholds.CPU, "CPU 单核占用阈值")
	ioP99Threshold := flag.Float64("io-p99-threshold-ms", defaultThresholds.IOP99Ms, "I/O P99 时延阈值(毫秒)")
	memAvailFloor := flag.Float64("mem-avail-floor-pct", defaultThresholds.MemAvailFloorPct, "内存可用占比下限(%)")
	lockOffcpuThreshold := flag.Float64("lock-offcpu-threshold", defaultThresholds.LockOffcpuRatio, "锁/阻塞 off-CPU 占比阈值")
	lockIncludeBlocking := flag.Bool("lock-include-blocking", false, "lock 场景保留未命中锁/同步符号的普通长阻塞报告")
	lockTopN := flag.Int("lock-topn", 5, "lock 场景每个窗口最多输出的 Top-N 阻塞线程")
	syscallRateThreshold := flag.Float64("syscall-rate-threshold", defaultThresholds.SyscallCallsPerSec, "系统调用频率阈值(次/秒)")
	targetPID := flag.Uint("target-pid", 0, "mem/lock/syscall 场景：只观测指定进程树 root pid（0=全局）")
	sustain := flag.Int("sustain", 3, "连续超过阈值多少个窗口才触发")
	duration := flag.Duration("duration", 0, "总运行时长（0 = 直到 Ctrl-C）")
	format := flag.String("format", "json", "输出格式：json(结束时单个会话)|jsonl(实时逐行)|yaml|md")
	allowPartial := flag.Bool("allow-partial", false, "允许 all 模式在 collector 初始化或采集失败后降级运行")
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
	if err := validateThresholds(th); err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(2)
	}
	if *interval <= 0 {
		fmt.Fprintln(os.Stderr, "配置错误: --interval 必须大于 0")
		os.Exit(2)
	}
	if *sustain < 1 {
		fmt.Fprintln(os.Stderr, "配置错误: --sustain 必须大于 0")
		os.Exit(2)
	}
	if *duration < 0 {
		fmt.Fprintln(os.Stderr, "配置错误: --duration 不能为负数")
		os.Exit(2)
	}
	if *lockTopN < 1 {
		fmt.Fprintln(os.Stderr, "配置错误: --lock-topn 必须大于 0")
		os.Exit(2)
	}
	if *targetPID > uint(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "配置错误: --target-pid 超出 uint32 范围")
		os.Exit(2)
	}
	if *allowPartial && *scenario != "all" {
		fmt.Fprintln(os.Stderr, "配置错误: --allow-partial 仅适用于 --scenario all")
		os.Exit(2)
	}
	formatName := strings.ToLower(*format)
	switch formatName {
	case "json", "jsonl", "yaml", "yml", "md", "markdown":
	default:
		fmt.Fprintf(os.Stderr, "配置错误: 未知格式 %q（支持 json|jsonl|yaml|md）\n", *format)
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
		scenario:     *scenario,
		interval:     *interval,
		threshold:    th,
		sustain:      *sustain,
		duration:     *duration,
		format:       formatName,
		targetPID:    uint32(*targetPID),
		allowPartial: *allowPartial,
		tracker:      newCollectorTracker(*scenario),
		lock: lockConfig{
			includeBlocking: *lockIncludeBlocking,
			topN:            *lockTopN,
		},
	}

	// JSON 会话与 Markdown 报告按 incident 聚合；JSONL/YAML/Markdown 单条实时输出。
	agg := report.New()
	var h handler
	if *reportPath != "" || cfg.format == "json" {
		h = func(r schema.AnomalyReport) error {
			agg.Add(finalizeReport(r))
			return nil
		}
	} else {
		h = func(r schema.AnomalyReport) error {
			return output.Write(out, finalizeReport(r), cfg.format)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	statsFD, statsErr := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if statsErr != nil {
		cfg.tracker.healthUnavailable(fmt.Errorf("enable BPF runtime stats: %w", statsErr))
		fmt.Fprintf(os.Stderr, "[ebpf-rca] 警告：无法启用 BPF runtime/run-count 统计：%v\n", statsErr)
	}
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
	if healthErr := cfg.tracker.failUnhealthy(); healthErr != nil && !cfg.allowPartial {
		runErr = errors.Join(runErr, healthErr)
	}
	if statsFD != nil {
		if err := statsFD.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "[ebpf-rca] 警告：关闭 BPF stats fd 失败：%v\n", err)
		}
	}
	cfg.tracker.finish()
	ended := time.Now()

	if *reportPath == "" && cfg.format == "json" {
		session := makeDiagnosticSession(cfg, start, ended, agg.Reports())
		if err := output.WriteSession(out, session); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("output session: %w", err))
		}
	}

	if *reportPath != "" {
		f, ferr := os.Create(*reportPath)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "open report:", ferr)
			os.Exit(1)
		}
		defer f.Close()
		if rerr := agg.RenderWithCollectors(f, ended.Sub(start), cfg.tracker.snapshot()); rerr != nil {
			fmt.Fprintln(os.Stderr, "render report:", rerr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[ebpf-rca] 诊断报告已写入 %s（%d 项）\n", *reportPath, agg.Count())
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "error:", runErr)
		fmt.Fprintln(os.Stderr, "提示：需要 root 或 CAP_BPF/CAP_PERFMON 权限，内核需启用 BTF。")
		os.Exit(1)
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

func validateThresholds(th thresholds) error {
	values := []struct {
		name  string
		value float64
	}{
		{"cpu-threshold", th.CPU},
		{"io-p99-threshold-ms", th.IOP99Ms},
		{"mem-avail-floor-pct", th.MemAvailFloorPct},
		{"lock-offcpu-threshold", th.LockOffcpuRatio},
		{"syscall-rate-threshold", th.SyscallCallsPerSec},
	}
	for _, item := range values {
		if math.IsNaN(item.value) || math.IsInf(item.value, 0) || item.value < 0 {
			return fmt.Errorf("--%s 必须是非负有限数", item.name)
		}
	}
	if th.MemAvailFloorPct > 100 {
		return fmt.Errorf("--mem-avail-floor-pct 不能超过 100")
	}
	return nil
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

// runLoop 驱动统一采样循环；Poll/输出错误立即返回给 main。
func runLoop(ctx context.Context, cfg config, tick func(time.Time) error) error {
	ticker, deadline, cancel := loopTimers(cfg)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline:
			return nil
		case now := <-ticker.C:
			if err := tick(now); err != nil {
				return err
			}
		}
	}
}

type collectorPollError struct {
	name string
	err  error
}

func (e *collectorPollError) Error() string { return fmt.Sprintf("poll %s: %v", e.name, e.err) }
func (e *collectorPollError) Unwrap() error { return e.err }

func markPollError(cfg config, name string, err error) error {
	cfg.tracker.failed(name, err)
	return &collectorPollError{name: name, err: err}
}

func runCPU(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewCPUCollector()
	if err != nil {
		cfg.tracker.failed("cpu", err)
		return err
	}
	defer col.Close()
	defer cfg.tracker.captureHealth("cpu", col)
	cfg.tracker.initialized("cpu")
	det := detector.NewCPUDetector(cfg.threshold.CPU, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=cpu interval=%s threshold=%.2f sustain=%d\n",
		cfg.interval, cfg.threshold.CPU, cfg.sustain)
	if _, err := col.Poll(cfg.interval); err != nil {
		return markPollError(cfg, "cpu", err)
	}
	cfg.tracker.pollOK("cpu", time.Now())
	return runLoop(ctx, cfg, func(now time.Time) error {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			return markPollError(cfg, "cpu", err)
		}
		cfg.tracker.pollOK("cpu", now)
		for _, sig := range det.Detect(samples) {
			resolveCPUHotStack(&sig, col)
			if err := h(rca.BuildCPUReport(sig, cfg.threshold.CPU)); err != nil {
				return fmt.Errorf("output cpu report: %w", err)
			}
		}
		return nil
	})
}

func runIO(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewIOCollector()
	if err != nil {
		cfg.tracker.failed("io", err)
		return err
	}
	defer col.Close()
	defer cfg.tracker.captureHealth("io", col)
	cfg.tracker.initialized("io")
	det := detector.NewIODetector(cfg.threshold.IOP99Ms, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=io interval=%s p99_threshold=%.1fms sustain=%d\n",
		cfg.interval, cfg.threshold.IOP99Ms, cfg.sustain)
	if _, err := col.Poll(cfg.interval); err != nil {
		return markPollError(cfg, "io", err)
	}
	cfg.tracker.pollOK("io", time.Now())
	return runLoop(ctx, cfg, func(now time.Time) error {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			return markPollError(cfg, "io", err)
		}
		cfg.tracker.pollOK("io", now)
		for _, sig := range det.Detect(samples) {
			if err := h(rca.BuildIOReport(sig, cfg.threshold.IOP99Ms)); err != nil {
				return fmt.Errorf("output io report: %w", err)
			}
		}
		return nil
	})
}

func runMem(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewMemCollector(cfg.targetPID, cfg.threshold.MemAvailFloorPct)
	if err != nil {
		cfg.tracker.failed("mem", err)
		return err
	}
	defer col.Close()
	defer cfg.tracker.captureHealth("mem", col)
	cfg.tracker.initialized("mem")
	det := detector.NewMemDetector(cfg.threshold.MemAvailFloorPct, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=mem interval=%s avail_floor=%.0f%% target_pid=%d sustain=%d\n",
		cfg.interval, cfg.threshold.MemAvailFloorPct, cfg.targetPID, cfg.sustain)
	if _, err := col.Poll(cfg.interval); err != nil {
		return markPollError(cfg, "mem", err)
	}
	cfg.tracker.pollOK("mem", time.Now())
	return runLoop(ctx, cfg, func(now time.Time) error {
		snap, err := col.Poll(cfg.interval)
		if err != nil {
			return markPollError(cfg, "mem", err)
		}
		cfg.tracker.pollOK("mem", now)
		for _, sig := range det.Detect(snap) {
			if err := h(rca.BuildMemReport(sig, cfg.threshold.MemAvailFloorPct)); err != nil {
				return fmt.Errorf("output mem report: %w", err)
			}
		}
		return nil
	})
}

func runLock(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewLockCollector(cfg.targetPID)
	if err != nil {
		cfg.tracker.failed("lock", err)
		return err
	}
	defer col.Close()
	defer cfg.tracker.captureHealth("lock", col)
	cfg.tracker.initialized("lock")
	det := detector.NewLockDetector(cfg.threshold.LockOffcpuRatio, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=lock interval=%s threshold=%.2f target_pid=%d sustain=%d include_blocking=%t topn=%d\n",
		cfg.interval, cfg.threshold.LockOffcpuRatio, cfg.targetPID, cfg.sustain, cfg.lock.includeBlocking, cfg.lock.topN)
	if _, err := col.Poll(cfg.interval); err != nil {
		return markPollError(cfg, "lock", err)
	}
	cfg.tracker.pollOK("lock", time.Now())
	return runLoop(ctx, cfg, func(now time.Time) error {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			return markPollError(cfg, "lock", err)
		}
		cfg.tracker.pollOK("lock", now)
		filtered, stacks := prepareLockSamples(samples, col.ResolveStack, cfg.lock)
		for _, sig := range det.Detect(filtered) {
			stack := stacks[lockKeyOf(sig.Sample)]
			if err := h(rca.BuildLockReport(sig, stack, cfg.threshold.LockOffcpuRatio)); err != nil {
				return fmt.Errorf("output lock report: %w", err)
			}
		}
		return nil
	})
}

func runSyscall(ctx context.Context, cfg config, h handler) error {
	col, err := collector.NewSyscallCollector(cfg.targetPID)
	if err != nil {
		cfg.tracker.failed("syscall", err)
		return err
	}
	defer col.Close()
	defer cfg.tracker.captureHealth("syscall", col)
	cfg.tracker.initialized("syscall")
	det := detector.NewSyscallDetector(cfg.threshold.SyscallCallsPerSec, cfg.sustain)
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=syscall interval=%s calls/s_floor=%.0f target_pid=%d sustain=%d\n",
		cfg.interval, cfg.threshold.SyscallCallsPerSec, cfg.targetPID, cfg.sustain)
	if _, err := col.Poll(cfg.interval); err != nil {
		return markPollError(cfg, "syscall", err)
	}
	cfg.tracker.pollOK("syscall", time.Now())
	return runLoop(ctx, cfg, func(now time.Time) error {
		samples, err := col.Poll(cfg.interval)
		if err != nil {
			return markPollError(cfg, "syscall", err)
		}
		cfg.tracker.pollOK("syscall", now)
		for _, sig := range det.Detect(samples) {
			if err := h(rca.BuildSyscallReport(sig, cfg.threshold.SyscallCallsPerSec, cfg.targetPID)); err != nil {
				return fmt.Errorf("output syscall report: %w", err)
			}
		}
		return nil
	})
}

type allCollectorTick struct {
	name   string
	active bool
	warmup func() error
	tick   func(time.Time) error
}

// runAll preflights all five collectors before the first Poll. Degradation is
// opt-in; by default any initialization or Poll failure terminates the session.
func runAll(ctx context.Context, cfg config, h handler) error {
	var ticks []allCollectorTick
	var initErrors []error
	initFailure := func(name string, err error) {
		cfg.tracker.failed(name, err)
		initErrors = append(initErrors, fmt.Errorf("initialize %s collector: %w", name, err))
		if cfg.allowPartial {
			fmt.Fprintf(os.Stderr, "[ebpf-rca] partial: collector %s 初始化失败：%v\n", name, err)
		}
	}

	if col, err := collector.NewCPUCollector(); err != nil {
		initFailure("cpu", err)
	} else {
		defer col.Close()
		defer cfg.tracker.captureHealth("cpu", col)
		cfg.tracker.initialized("cpu")
		det := detector.NewCPUDetector(cfg.threshold.CPU, cfg.sustain)
		ticks = append(ticks, allCollectorTick{
			name: "cpu", active: true,
			warmup: func() error { _, err := col.Poll(cfg.interval); return err },
			tick: func(now time.Time) error {
				samples, err := col.Poll(cfg.interval)
				if err != nil {
					return markPollError(cfg, "cpu", err)
				}
				cfg.tracker.pollOK("cpu", now)
				for _, sig := range det.Detect(samples) {
					resolveCPUHotStack(&sig, col)
					if err := h(rca.BuildCPUReport(sig, cfg.threshold.CPU)); err != nil {
						return fmt.Errorf("output cpu report: %w", err)
					}
				}
				return nil
			},
		})
	}

	if col, err := collector.NewIOCollector(); err != nil {
		initFailure("io", err)
	} else {
		defer col.Close()
		defer cfg.tracker.captureHealth("io", col)
		cfg.tracker.initialized("io")
		det := detector.NewIODetector(cfg.threshold.IOP99Ms, cfg.sustain)
		ticks = append(ticks, allCollectorTick{
			name: "io", active: true,
			warmup: func() error { _, err := col.Poll(cfg.interval); return err },
			tick: func(now time.Time) error {
				samples, err := col.Poll(cfg.interval)
				if err != nil {
					return markPollError(cfg, "io", err)
				}
				cfg.tracker.pollOK("io", now)
				for _, sig := range det.Detect(samples) {
					if err := h(rca.BuildIOReport(sig, cfg.threshold.IOP99Ms)); err != nil {
						return fmt.Errorf("output io report: %w", err)
					}
				}
				return nil
			},
		})
	}

	if col, err := collector.NewMemCollector(cfg.targetPID, cfg.threshold.MemAvailFloorPct); err != nil {
		initFailure("mem", err)
	} else {
		defer col.Close()
		defer cfg.tracker.captureHealth("mem", col)
		cfg.tracker.initialized("mem")
		det := detector.NewMemDetector(cfg.threshold.MemAvailFloorPct, cfg.sustain)
		ticks = append(ticks, allCollectorTick{
			name: "mem", active: true,
			warmup: func() error { _, err := col.Poll(cfg.interval); return err },
			tick: func(now time.Time) error {
				snap, err := col.Poll(cfg.interval)
				if err != nil {
					return markPollError(cfg, "mem", err)
				}
				cfg.tracker.pollOK("mem", now)
				for _, sig := range det.Detect(snap) {
					if err := h(rca.BuildMemReport(sig, cfg.threshold.MemAvailFloorPct)); err != nil {
						return fmt.Errorf("output mem report: %w", err)
					}
				}
				return nil
			},
		})
	}

	if col, err := collector.NewLockCollector(cfg.targetPID); err != nil {
		initFailure("lock", err)
	} else {
		defer col.Close()
		defer cfg.tracker.captureHealth("lock", col)
		cfg.tracker.initialized("lock")
		det := detector.NewLockDetector(cfg.threshold.LockOffcpuRatio, cfg.sustain)
		ticks = append(ticks, allCollectorTick{
			name: "lock", active: true,
			warmup: func() error { _, err := col.Poll(cfg.interval); return err },
			tick: func(now time.Time) error {
				samples, err := col.Poll(cfg.interval)
				if err != nil {
					return markPollError(cfg, "lock", err)
				}
				cfg.tracker.pollOK("lock", now)
				filtered, stacks := prepareLockSamples(samples, col.ResolveStack, cfg.lock)
				for _, sig := range det.Detect(filtered) {
					if err := h(rca.BuildLockReport(sig, stacks[lockKeyOf(sig.Sample)], cfg.threshold.LockOffcpuRatio)); err != nil {
						return fmt.Errorf("output lock report: %w", err)
					}
				}
				return nil
			},
		})
	}

	if col, err := collector.NewSyscallCollector(cfg.targetPID); err != nil {
		initFailure("syscall", err)
	} else {
		defer col.Close()
		defer cfg.tracker.captureHealth("syscall", col)
		cfg.tracker.initialized("syscall")
		det := detector.NewSyscallDetector(cfg.threshold.SyscallCallsPerSec, cfg.sustain)
		ticks = append(ticks, allCollectorTick{
			name: "syscall", active: true,
			warmup: func() error { _, err := col.Poll(cfg.interval); return err },
			tick: func(now time.Time) error {
				samples, err := col.Poll(cfg.interval)
				if err != nil {
					return markPollError(cfg, "syscall", err)
				}
				cfg.tracker.pollOK("syscall", now)
				for _, sig := range det.Detect(samples) {
					if err := h(rca.BuildSyscallReport(sig, cfg.threshold.SyscallCallsPerSec, cfg.targetPID)); err != nil {
						return fmt.Errorf("output syscall report: %w", err)
					}
				}
				return nil
			},
		})
	}
	if len(initErrors) > 0 && !cfg.allowPartial {
		return fmt.Errorf("collector preflight failed: %w", errors.Join(initErrors...))
	}

	// No detector sees data until every requested collector has finished loading.
	active := 0
	for i := range ticks {
		if err := ticks[i].warmup(); err != nil {
			err = markPollError(cfg, ticks[i].name, err)
			if !cfg.allowPartial {
				return err
			}
			ticks[i].active = false
			fmt.Fprintf(os.Stderr, "[ebpf-rca] partial: collector %s 首次 Poll 失败：%v\n", ticks[i].name, err)
			continue
		}
		cfg.tracker.pollOK(ticks[i].name, time.Now())
		active++
	}
	if active == 0 {
		return fmt.Errorf("无任何 collector 可继续采集")
	}
	fmt.Fprintf(os.Stderr, "[ebpf-rca] 场景=all 已启动 %d/5 个场景 interval=%s sustain=%d partial=%t\n",
		active, cfg.interval, cfg.sustain, cfg.tracker.partial)
	return runLoop(ctx, cfg, func(now time.Time) error {
		active = 0
		for i := range ticks {
			if !ticks[i].active {
				continue
			}
			active++
			if err := ticks[i].tick(now); err != nil {
				var pollErr *collectorPollError
				if cfg.allowPartial && errors.As(err, &pollErr) {
					ticks[i].active = false
					active--
					fmt.Fprintf(os.Stderr, "[ebpf-rca] partial: %v；停用该 collector\n", err)
					continue
				}
				return err
			}
		}
		if active == 0 {
			return fmt.Errorf("所有 collector 均已失败")
		}
		return nil
	})
}

func resolveCPUHotStack(sig *detector.Signal, col *collector.CPUCollector) {
	if sig == nil || col == nil || !sig.Sample.HotStackValid {
		return
	}
	sig.Sample.HotStack = col.ResolveUserStack(sig.Sample.Pid, sig.Sample.HotStackID, 8)
}

type lockCandidate struct {
	sample collector.LockSample
	stack  []string
}

type lockSampleKey struct {
	pid     uint32
	tid     uint32
	address uint64
	stackID int32
}

func lockKeyOf(sample collector.LockSample) lockSampleKey {
	return lockSampleKey{pid: sample.Pid, tid: sample.Tid, address: sample.LockAddress, stackID: sample.StackID}
}

func prepareLockSamples(samples []collector.LockSample, resolve func(int32, int) []string, cfg lockConfig) ([]collector.LockSample, map[lockSampleKey][]string) {
	candidates := make([]lockCandidate, 0, len(samples))
	for _, sample := range samples {
		stack := resolve(sample.StackID, 8)
		if !cfg.includeBlocking && !sample.Futex && !rca.StackHasLock(stack) {
			continue
		}
		candidates = append(candidates, lockCandidate{sample: sample, stack: stack})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i].sample, candidates[j].sample
		if a.OffcpuRatio != b.OffcpuRatio {
			return a.OffcpuRatio > b.OffcpuRatio
		}
		if a.MaxOffcpuMs != b.MaxOffcpuMs {
			return a.MaxOffcpuMs > b.MaxOffcpuMs
		}
		if a.BlockCount != b.BlockCount {
			return a.BlockCount > b.BlockCount
		}
		if a.Pid != b.Pid {
			return a.Pid < b.Pid
		}
		return a.LockAddress < b.LockAddress
	})
	if cfg.topN > 0 && len(candidates) > cfg.topN {
		candidates = candidates[:cfg.topN]
	}
	out := make([]collector.LockSample, 0, len(candidates))
	stacks := make(map[lockSampleKey][]string, len(candidates))
	for _, c := range candidates {
		out = append(out, c.sample)
		stacks[lockKeyOf(c.sample)] = c.stack
	}
	return out, stacks
}
