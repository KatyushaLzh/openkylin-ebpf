package rca

import (
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func BuildMemReport(sig detector.MemSignal, availFloorPct float64) schema.AnomalyReport {
	snap := sig.Snapshot
	culprit := sig.Culprit
	root, suggestion, confidence := classifyMem(sig)
	rootCode := schema.RootCauseMemReclaimPressure
	anomalyType := "内存回收压力"
	if sig.OOM {
		rootCode = schema.RootCauseMemOOMVictim
		anomalyType = "OOM事件"
	}

	evidence := []schema.Evidence{
		{Type: "metric", Name: "mem_available_pct", Value: round2(snap.MemAvailablePct),
			Threshold: availFloorPct, Desc: "系统可用内存占比"},
		{Type: "metric", Name: "memory_psi_some_pct", Value: round2(snap.PSISomePct),
			Threshold: collector.MemPSISomeSignalPct, Desc: "窗口内至少一个任务因内存压力停顿的时间占比"},
		{Type: "metric", Name: "memory_psi_full_pct", Value: round2(snap.PSIFullPct),
			Threshold: collector.MemPSIFullSignalPct, Desc: "窗口内所有非 idle 任务均因内存压力停顿的时间占比"},
		{Type: "metric", Name: "direct_reclaim_ms_per_sec", Value: round2(snap.DirectReclaimMsPerSec),
			Threshold: collector.MemDirectReclaimSignalMsPerSec, Desc: "系统窗口内 direct reclaim 墙钟速率"},
		{Type: "event", Name: "oom_victim_count", Value: snap.OOMVictimCount,
			Desc: "tp_btf/mark_victim 捕获的 OOM victim 数"},
		{Type: "event", Name: "kswapd_wakes", Value: snap.KswapdWakes,
			Desc: "辅助证据：窗口内 kswapd 唤醒次数"},
		{Type: "event", Name: "pgscan_direct", Value: snap.PgscanDirect,
			Desc: "窗口内 /proc/vmstat direct scan 增量"},
		{Type: "event", Name: "pgscan_kswapd", Value: snap.PgscanKswapd,
			Desc: "窗口内 /proc/vmstat kswapd scan 增量"},
		{Type: "event", Name: "direct_reclaim_count", Value: culprit.DirectReclaimCount,
			Desc: "归因进程窗口内 direct reclaim 次数"},
		{Type: "metric", Name: "direct_reclaim_ms", Value: round2(culprit.DirectReclaimMs),
			Desc: "归因进程 direct reclaim 累计耗时"},
		{Type: "metric", Name: "major_fault_per_sec", Value: round2(culprit.MajFltPerSec),
			Threshold: collector.MemMajorFaultSignalPerSec, Desc: "归因进程 major fault 速率"},
		{Type: "metric", Name: "anon_rss_growth_kb_per_sec", Value: round2(culprit.AnonRSSGrowthKBPerSec),
			Threshold: collector.MemAnonRSSGrowthSignalKBPerSec, Desc: "归因进程匿名 RSS 增长速率"},
	}

	related := schema.RelatedObject{Scope: "system"}
	if culprit.Pid != 0 {
		scope := "process"
		if snap.Targeted {
			scope = "target_tree"
		}
		related = schema.RelatedObject{Pid: culprit.Pid, Comm: culprit.Comm, Scope: scope}
	}

	return schema.AnomalyReport{
		AnomalyType:   anomalyType,
		RootCauseCode: rootCode,
		RelatedObject: related,
		KeyMetrics: map[string]interface{}{
			"mem_available_pct":          round2(snap.MemAvailablePct),
			"memory_psi_some_pct":        round2(snap.PSISomePct),
			"memory_psi_full_pct":        round2(snap.PSIFullPct),
			"direct_reclaim_ms_per_sec":  round2(snap.DirectReclaimMsPerSec),
			"oom_victim_count":           snap.OOMVictimCount,
			"direct_reclaim_count":       culprit.DirectReclaimCount,
			"major_fault_per_sec":        round2(culprit.MajFltPerSec),
			"anon_rss_growth_kb_per_sec": round2(culprit.AnonRSSGrowthKBPerSec),
			"pgscan_direct":              snap.PgscanDirect,
			"pgscan_kswapd":              snap.PgscanKswapd,
		},
		TimeWindow:         timeWindow(sig.Window),
		SuspectedRootCause: root,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

func classifyMem(sig detector.MemSignal) (root, suggestion string, confidence float64) {
	culprit := sig.Culprit
	if sig.OOM {
		if culprit.Pid != 0 {
			return "内核已将该进程标记为 OOM victim；这是 mark_victim 事件而非风险预测",
				"立即检查该进程工作集与 cgroup memory 事件；设置 memory.high 做提前节流，并复核 OOM 选择原因",
				0.99
		}
		return "内核已发生 OOM victim 事件，但 victim 不在目标进程树内，按系统范围报告",
			"检查系统 OOM 日志和各 cgroup memory.events；不要把目标树之外的 PID 伪归因给目标进程",
			0.95
	}
	if culprit.DirectReclaimCount > 0 || culprit.DirectReclaimMs > 0 {
		return "系统内存压力与该进程 direct reclaim 同窗出现，分配路径被同步回收阻塞",
			"检查该进程分配速率、泄漏和工作集；用 memory.high 提前节流，或扩容并降低并发工作集",
			0.92
	}
	if culprit.AnonRSSGrowthKBPerSec >= collector.MemAnonRSSGrowthSignalKBPerSec {
		return "系统内存压力与该进程匿名 RSS 快速增长同窗出现，疑似内存突增或泄漏",
			"采样 heap/smaps 定位匿名内存增长路径；限制缓存与批量大小，并设置 cgroup 内存水位",
			0.86
	}
	if culprit.MajFltPerSec >= collector.MemMajorFaultSignalPerSec {
		return "系统内存压力与该进程高 major-fault 速率同窗出现，工作集频繁从后备存储恢复",
			"缩小工作集或扩容内存；结合块 I/O 时延确认换入/文件回源成本",
			0.8
	}
	return "系统已满足内存压力与进程贡献联合条件，但目标树内无法定位肇事进程",
		"按系统范围检查 PSI、vmstat 与 cgroup memory.events，再缩小观测目标",
		0.65
}
