// Package rca 是确定性根因推断引擎。
//
// 设计原则（正面回应赛题"降低模型幻觉"）：核心判定全部基于采集到的真实指标与
// 显式规则不依赖 LLM；每条结论仍必须由可追溯的采集证据与阈值条件支撑。
// LLM 仅在上层"自动生成自然语言报告"时可选接入，且必须以本结构为输入。
package rca

import (
	"math"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

// BuildCPUReport 将一次 CPU 异常信号转换为结构化诊断报告。
func BuildCPUReport(sig detector.Signal, threshold float64) schema.AnomalyReport {
	s := sig.Sample
	rootCause, rootCauseCode, suggestion, confidence := classifyCPU(s, threshold)
	triggerCores := math.Max(s.CPUUtil, s.ProcessCPUCores)

	evidence := []schema.Evidence{
		{
			Type: "metric", Name: "cpu_util",
			Value: round2(s.CPUUtil), Threshold: threshold,
			Desc: "兼容指标：窗口内最高占用 TID 的单核 CPU 占用",
		},
		{
			Type: "metric", Name: "cpu_trigger_cores",
			Value: round2(triggerCores), Threshold: threshold,
			Desc: "最热线程或进程合计 CPU 核数持续高于阈值",
		},
		{
			Type: "metric", Name: "top_thread_cpu_cores",
			Value: round2(s.CPUUtil),
			Desc:  "窗口内最高占用 TID 的 CPU 核数",
		},
		{
			Type: "metric", Name: "process_cpu_cores",
			Value: round2(s.ProcessCPUCores),
			Desc:  "同一 TGID 所有线程 CPU 核数之和",
		},
		{
			Type: "metric", Name: "ctx_switch_per_min",
			Value: round2(s.CtxPerMin),
			Desc:  "采样窗口内上下文切换频次",
		},
		{
			Type: "metric", Name: "runq_wait_us",
			Value: round2(s.RunqWaitUs),
			Desc:  "按真实入队次数计算的平均运行队列等待时间(微秒)",
		},
	}
	if len(s.HotStack) > 0 {
		evidence = append(evidence, schema.Evidence{
			Type: "stack", Name: "user_hot_stack", Value: s.HotStack,
			Func: s.HotStack[0], Desc: "单次连续运行不少于 5ms 的用户栈聚合",
		})
	}

	return schema.AnomalyReport{
		AnomalyType:   "CPU异常占用",
		RootCauseCode: rootCauseCode,
		RelatedObject: schema.RelatedObject{
			Pid:   s.Pid,
			Tid:   s.Tid,
			Comm:  s.Comm,
			Scope: "process",
		},
		KeyMetrics: map[string]interface{}{
			"cpu_util":             round2(s.CPUUtil),
			"top_thread_cpu_cores": round2(s.CPUUtil),
			"process_cpu_cores":    round2(s.ProcessCPUCores),
			"ctx_switch_per_min":   round2(s.CtxPerMin),
			"runq_wait_us":         round2(s.RunqWaitUs),
			"runq_count":           s.RunqCount,
			"hot_stack_samples":    s.HotStackSamples,
		},
		TimeWindow:         timeWindow(sig.Window),
		SuspectedRootCause: rootCause,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

// classifyCPU never infers lock contention from context-switch frequency.
// Runqueue delay supports scheduler pressure; lock attribution requires an
// independently correlated lock report and is intentionally outside this rule.
func classifyCPU(s collector.Sample, threshold float64) (root, code, suggestion string, confidence float64) {
	confidence = 0.85
	if math.Max(s.CPUUtil, s.ProcessCPUCores) >= math.Max(threshold, 0.95) {
		confidence = 0.93
	}
	if s.RunqCount > 0 && s.RunqWaitUs >= 1000 {
		return "进程 CPU 需求伴随显著运行队列等待，系统调度容量存在压力",
			schema.RootCauseCPUSchedulerPressure,
			"检查系统级 runnable 任务数、CPU 配额与亲和性；扩容或降低并发后复测运行队列等待",
			confidence
	}
	return "用户态计算热点导致 CPU 饱和（计算密集或异常 busy loop）",
		schema.RootCauseCPUComputeHotspot,
		"定位用户态热点函数，优化算法或并行度；排查是否存在异常 busy loop",
		confidence
}

func round2(f float64) float64 {
	return math.Round(f*100) / 100
}

func timeWindow(window collector.ObservationWindow) schema.TimeWindow {
	return schema.TimeWindow{
		Start:     window.Start.UTC().Format(time.RFC3339Nano),
		End:       window.End.UTC().Format(time.RFC3339Nano),
		ElapsedMS: float64(window.Elapsed.Nanoseconds()) / 1e6,
	}
}
