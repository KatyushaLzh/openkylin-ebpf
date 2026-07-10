package rca

import (
	"fmt"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/syscalls"
)

// 单次平均耗时超过该值(微秒)判为"高耗时型"，否则为"高频型"。
const syscallHighLatUs = 1000.0

// 单个 syscall 每秒累计耗时超过该值也可触发热点。
const syscallTimeMsPerSecFloor = 300.0

// BuildSyscallReport 将一次系统调用热点信号转换为结构化诊断报告。
func BuildSyscallReport(sig detector.SyscallSignal, callsPerSecThreshold float64, targetPID uint32) schema.AnomalyReport {
	s := sig.Sample
	root, code, suggestion, confidence := classifySyscall(s)
	scope := "process"
	if targetPID != 0 {
		scope = "target_tree"
	}

	evidence := []schema.Evidence{
		{Type: "metric", Name: "syscall", Value: s.Syscall, Desc: "热点系统调用名"},
		{Type: "metric", Name: "syscall_nr", Value: s.Nr, Desc: "热点系统调用号"},
		{Type: "metric", Name: "calls_per_sec", Value: round2(s.CallsPerSec), Threshold: callsPerSecThreshold, Desc: "每秒调用次数"},
		{Type: "metric", Name: "avg_lat_us", Value: round2(s.AvgLatUs), Desc: "单次平均耗时(微秒)"},
		{Type: "metric", Name: "p99_lat_us", Value: round2(s.P99LatUs), Desc: "按直方图 bucket 上界估算的 P99 耗时(微秒)"},
		{Type: "metric", Name: "max_lat_us", Value: round2(s.MaxLatUs), Desc: "单次最大耗时(微秒)"},
		{Type: "metric", Name: "total_ms_per_sec", Value: round2(s.TotalMsPerSec),
			Threshold: syscallTimeMsPerSecFloor, Desc: "每秒累计占用时间(毫秒)，反映累计耗时占比"},
		{Type: "metric", Name: "target_pid", Value: targetPID, Desc: "用户配置的进程过滤目标；0 表示全局观测"},
	}

	return schema.AnomalyReport{
		AnomalyType:   "系统调用热点",
		RootCauseCode: code,
		RelatedObject: schema.RelatedObject{
			Pid:   s.Pid,
			Comm:  s.Comm,
			Scope: scope,
		},
		KeyMetrics: map[string]interface{}{
			"syscall":          s.Syscall,
			"syscall_nr":       s.Nr,
			"calls_per_sec":    round2(s.CallsPerSec),
			"avg_lat_us":       round2(s.AvgLatUs),
			"p99_lat_us":       round2(s.P99LatUs),
			"max_lat_us":       round2(s.MaxLatUs),
			"total_ms_per_sec": round2(s.TotalMsPerSec),
			"target_pid":       targetPID,
		},
		TimeWindow:         timeWindow(sig.Window),
		SuspectedRootCause: root,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

func classifySyscall(s collector.SyscallSample) (root, code, suggestion string, confidence float64) {
	if syscalls.IsWaitingName(s.Syscall) {
		return fmt.Sprintf("等待型系统调用高频热点：%s 达 %.0f 次/秒，疑似短 timeout 轮询或唤醒风暴",
				s.Syscall, s.CallsPerSec),
			schema.RootCauseSyscallHighFrequency,
			fmt.Sprintf("检查 %s 调用的 timeout、事件源与唤醒条件；用阻塞等待或批处理降低空轮询频率", s.Syscall),
			0.82
	}
	if s.AvgLatUs >= syscallHighLatUs {
		return fmt.Sprintf("高耗时系统调用热点：%s 单次平均 %.0fµs，疑似阻塞型调用(如 fsync/慢 I/O/锁等待)",
				s.Syscall, s.AvgLatUs),
			schema.RootCauseSyscallHighLatency,
			fmt.Sprintf("排查 %s 的阻塞来源，合并/异步化该调用，降低同步等待", s.Syscall),
			0.88
	}
	return fmt.Sprintf("高频系统调用热点：%s 达 %.0f 次/秒，疑似忙轮询或调用未做批处理",
			s.Syscall, s.CallsPerSec),
		schema.RootCauseSyscallHighFrequency,
		fmt.Sprintf("减少 %s 调用频次：改用事件通知(epoll)/批量读写/缓存，避免忙轮询", s.Syscall),
		0.85
}
