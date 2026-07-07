package rca

import (
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

// BuildMemReport 将一次内存抖动信号转换为结构化诊断报告。
func BuildMemReport(sig detector.MemSignal, availFloorPct float64) schema.AnomalyReport {
	snap := sig.Snapshot
	c := sig.Culprit
	root, suggestion, confidence := classifyMem(c)

	evidence := []schema.Evidence{
		{Type: "metric", Name: "mem_available_pct", Value: round2(snap.MemAvailablePct),
			Threshold: availFloorPct, Desc: "可用内存占比持续低于阈值"},
		{Type: "event", Name: "kswapd_wakes", Value: snap.KswapdWakes,
			Desc: "窗口内 kswapd 后台回收唤醒次数"},
		{Type: "event", Name: "direct_reclaim_count", Value: c.DirectReclaimCount,
			Desc: "肇事进程窗口内直接回收次数(分配时被迫回收)"},
		{Type: "metric", Name: "direct_reclaim_ms", Value: round2(c.DirectReclaimMs),
			Desc: "肇事进程直接回收累计耗时"},
		{Type: "metric", Name: "major_fault", Value: c.MajFlt, Desc: "窗口内 major page fault 增量"},
		{Type: "metric", Name: "minor_fault", Value: c.MinFlt, Desc: "窗口内 minor page fault 增量"},
		{Type: "metric", Name: "rss_kb", Value: c.RSSKB, Desc: "进程 RSS 采样值(kB)"},
		{Type: "metric", Name: "anon_rss_kb", Value: c.AnonRSSKB, Desc: "进程匿名 RSS 采样值(kB)"},
		{Type: "metric", Name: "rss_delta_kb", Value: c.RSSDeltaKB, Desc: "窗口内 RSS 增量(kB)"},
		{Type: "metric", Name: "anon_rss_delta_kb", Value: c.AnonRSSDeltaKB, Desc: "窗口内匿名 RSS 增量(kB)"},
	}

	related := schema.RelatedObject{}
	if c.Pid != 0 {
		related = schema.RelatedObject{Pid: c.Pid, Comm: c.Comm}
	}

	return schema.AnomalyReport{
		AnomalyType:   "内存抖动",
		RelatedObject: related,
		KeyMetrics: map[string]interface{}{
			"mem_available_pct":    round2(snap.MemAvailablePct),
			"kswapd_wakes":         snap.KswapdWakes,
			"direct_reclaim_count": c.DirectReclaimCount,
			"major_fault":          c.MajFlt,
			"rss_kb":               c.RSSKB,
			"anon_rss_kb":          c.AnonRSSKB,
			"rss_delta_kb":         c.RSSDeltaKB,
			"anon_rss_delta_kb":    c.AnonRSSDeltaKB,
		},
		TimeWindow:         timeWindow(sig.WindowStart, sig.WindowEnd),
		SuspectedRootCause: root,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

func classifyMem(c collector.MemProc) (root, suggestion string, confidence float64) {
	if c.DirectReclaimCount > 0 {
		return "业务进程持续申请内存触发直接回收(direct reclaim)，导致回收压力上升与内存抖动",
			"排查该进程的内存申请/泄漏；限制其内存(cgroup memory.high)，或扩容内存、降低工作集",
			0.9
	}
	if c.MajFlt > 0 {
		return "可用内存偏低且 major fault 升高，疑似工作集超出物理内存导致换入/回源磁盘",
			"评估扩容内存或减少常驻内存；检查是否缓存与业务内存竞争",
			0.75
	}
	if c.RSSDeltaKB >= collector.MemRSSGrowthSignalKB || c.AnonRSSDeltaKB >= collector.MemRSSGrowthSignalKB {
		return "业务进程 RSS/匿名 RSS 在采样窗口内快速增长，疑似内存突增或泄漏导致系统压力上升",
			"检查该进程近期分配路径、缓存增长与对象生命周期；必要时加 cgroup 限额并采样 heap/smaps",
			0.8
	}
	if c.Pid != 0 && c.RSSKB > 0 {
		return "系统可用内存持续偏低，最大 RSS 进程可能贡献主要内存占用（未观察到 direct reclaim）",
			"检查该进程匿名内存与缓存占用；必要时结合 /proc/smaps 或 cgroup memory 进一步确认",
			0.68
	}
	return "系统可用内存持续偏低，存在 OOM 风险（未定位到单一肇事进程）",
		"检查整体内存分配与缓存占用，必要时调整 vm.* 参数或扩容内存",
		0.6
}
