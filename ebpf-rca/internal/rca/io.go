package rca

import (
	"fmt"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

// 队列深度超过该值视为"设备队列拥堵"。
const queueCongestionDepth = 16

// BuildIOReport 将一次 I/O 延迟抖动信号转换为结构化诊断报告。
func BuildIOReport(sig detector.IOSignal, p99ThresholdMs float64) schema.AnomalyReport {
	s := sig.Sample
	root, rootCauseCode, suggestion, confidence := classifyIO(s)

	evidence := []schema.Evidence{
		{Type: "metric", Name: "p99_lat_ms", Value: round2(s.P99LatMs), Threshold: p99ThresholdMs,
			Desc: "请求完成时延 P99"},
		{Type: "metric", Name: "avg_lat_ms", Value: round2(s.AvgLatMs), Desc: "平均完成时延"},
		{Type: "metric", Name: "max_lat_ms", Value: round2(s.MaxLatMs), Desc: "最大完成时延"},
		{Type: "metric", Name: "iops", Value: round2(s.IOPS), Desc: "每秒完成请求数"},
		{Type: "metric", Name: "throughput_mbps", Value: round2(s.ThroughputMBps), Desc: "吞吐(MB/s)"},
		{Type: "metric", Name: "avg_queue_depth", Value: round2(s.AverageQueueDepth),
			Threshold: queueCongestionDepth, Desc: "窗口内按时间积分的平均在途请求数"},
		{Type: "metric", Name: "queue_depth", Value: s.QueueDepth, Desc: "窗口结束时在途请求数(gauge)"},
	}

	return schema.AnomalyReport{
		AnomalyType:   "I/O延迟抖动",
		RootCauseCode: rootCauseCode,
		RelatedObject: schema.RelatedObject{
			Device: s.DevName,
		},
		KeyMetrics: map[string]interface{}{
			"p99_lat_ms":      round2(s.P99LatMs),
			"avg_lat_ms":      round2(s.AvgLatMs),
			"max_lat_ms":      round2(s.MaxLatMs),
			"iops":            round2(s.IOPS),
			"throughput_mbps": round2(s.ThroughputMBps),
			"avg_queue_depth": round2(s.AverageQueueDepth),
			"queue_depth":     s.QueueDepth,
		},
		TimeWindow:         timeWindow(sig.Window),
		SuspectedRootCause: root,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

func classifyIO(s collector.IOSample) (root, code, suggestion string, confidence float64) {
	if s.AverageQueueDepth >= queueCongestionDepth {
		return fmt.Sprintf("块设备服务队列拥堵（时间加权平均队列深度 %.2f）", s.AverageQueueDepth),
			schema.RootCauseIOQueueCongestion,
			"降低并发/队列深度(iodepth)，或评估更高 IOPS 的存储；排查是否随机小块写密集",
			0.9
	}
	return "块设备请求服务时延异常，但没有足够队列深度证据支持队列拥堵",
		schema.RootCauseIODeviceLatency,
		"检查设备固件、介质错误、限速与后端存储时延；当前证据不足以推断热点文件或缓存失效",
		0.86
}
