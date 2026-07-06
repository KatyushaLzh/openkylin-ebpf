package rca

import (
	"fmt"
	"time"

	"github.com/os2026/ebpf-rca/internal/collector"
	"github.com/os2026/ebpf-rca/internal/detector"
	"github.com/os2026/ebpf-rca/internal/schema"
)

// 队列深度超过该值视为"设备队列拥堵"。
const queueCongestionDepth = 16

// BuildIOReport 将一次 I/O 延迟抖动信号转换为结构化诊断报告。
func BuildIOReport(sig detector.IOSignal, p99ThresholdMs float64) schema.AnomalyReport {
	s := sig.Sample
	root, suggestion, confidence := classifyIO(s)

	evidence := []schema.Evidence{
		{Type: "metric", Name: "p99_lat_ms", Value: round2(s.P99LatMs), Threshold: p99ThresholdMs,
			Desc: "请求完成时延 P99"},
		{Type: "metric", Name: "avg_lat_ms", Value: round2(s.AvgLatMs), Desc: "平均完成时延"},
		{Type: "metric", Name: "max_lat_ms", Value: round2(s.MaxLatMs), Desc: "最大完成时延"},
		{Type: "metric", Name: "iops", Value: round2(s.IOPS), Desc: "每秒完成请求数"},
		{Type: "metric", Name: "throughput_mbps", Value: round2(s.ThroughputMBps), Desc: "吞吐(MB/s)"},
		{Type: "metric", Name: "queue_depth", Value: s.QueueDepth, Desc: "当前在途请求数(队列深度)"},
	}

	return schema.AnomalyReport{
		AnomalyType: "I/O延迟抖动",
		RelatedObject: schema.RelatedObject{
			Device: s.DevName,
		},
		KeyMetrics: map[string]interface{}{
			"p99_lat_ms":      round2(s.P99LatMs),
			"avg_lat_ms":      round2(s.AvgLatMs),
			"max_lat_ms":      round2(s.MaxLatMs),
			"iops":            round2(s.IOPS),
			"throughput_mbps": round2(s.ThroughputMBps),
			"queue_depth":     s.QueueDepth,
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

func classifyIO(s collector.IOSample) (root, suggestion string, confidence float64) {
	if s.QueueDepth >= queueCongestionDepth {
		return fmt.Sprintf("随机读写压力导致设备队列拥堵（队列深度 %d，队列过深）", s.QueueDepth),
			"降低并发/队列深度(iodepth)，或评估更高 IOPS 的存储；排查是否随机小块写密集",
			0.9
	}
	return "I/O 时延抖动，疑似热点设备访问集中或页缓存失效导致回源磁盘",
		"排查热点文件/设备访问模式，增大缓存命中或顺序化访问；必要时分散负载到多设备",
		0.78
}
