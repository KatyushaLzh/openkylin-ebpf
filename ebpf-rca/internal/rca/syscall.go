package rca

import (
	"fmt"
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
	"github.com/os2026/ebpf-rca/internal/detector"
	"github.com/os2026/ebpf-rca/internal/schema"
)

// 单次平均耗时超过该值(微秒)判为"高耗时型"，否则为"高频型"。
const syscallHighLatUs = 1000.0

// BuildSyscallReport 将一次系统调用热点信号转换为结构化诊断报告。
func BuildSyscallReport(sig detector.SyscallSignal) schema.AnomalyReport {
	s := sig.Sample
	root, suggestion, confidence := classifySyscall(s)

	evidence := []schema.Evidence{
		{Type: "metric", Name: "syscall", Value: s.Syscall, Desc: "热点系统调用名"},
		{Type: "metric", Name: "calls_per_sec", Value: round2(s.CallsPerSec), Desc: "每秒调用次数"},
		{Type: "metric", Name: "avg_lat_us", Value: round2(s.AvgLatUs), Desc: "单次平均耗时(微秒)"},
		{Type: "metric", Name: "max_lat_us", Value: round2(s.MaxLatUs), Desc: "单次最大耗时(微秒)"},
		{Type: "metric", Name: "total_ms_per_sec", Value: round2(s.TotalMsPerSec),
			Desc: "每秒累计占用时间(毫秒)，反映累计耗时占比"},
	}

	return schema.AnomalyReport{
		AnomalyType: "系统调用热点",
		RelatedObject: schema.RelatedObject{
			Pid:  s.Pid,
			Comm: s.Comm,
		},
		KeyMetrics: map[string]interface{}{
			"syscall":          s.Syscall,
			"calls_per_sec":    round2(s.CallsPerSec),
			"avg_lat_us":       round2(s.AvgLatUs),
			"total_ms_per_sec": round2(s.TotalMsPerSec),
		},
		TimeWindow: schema.TimeWindow{
			Start: sig.WindowStart.UTC().Format(time.RFC3339),
			End:   sig.WindowEnd.UTC().Format(time.RFC3339),
		},
		SuspectedRootCause: root,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

func classifySyscall(s collector.SyscallSample) (root, suggestion string, confidence float64) {
	if s.AvgLatUs >= syscallHighLatUs {
		return fmt.Sprintf("高耗时系统调用热点：%s 单次平均 %.0fµs，疑似阻塞型调用(如 fsync/慢 I/O/锁等待)",
				s.Syscall, s.AvgLatUs),
			fmt.Sprintf("排查 %s 的阻塞来源，合并/异步化该调用，降低同步等待", s.Syscall),
			0.88
	}
	return fmt.Sprintf("高频系统调用热点：%s 达 %.0f 次/秒，疑似忙轮询或调用未做批处理",
			s.Syscall, s.CallsPerSec),
		fmt.Sprintf("减少 %s 调用频次：改用事件通知(epoll)/批量读写/缓存，避免忙轮询", s.Syscall),
		0.85
}
