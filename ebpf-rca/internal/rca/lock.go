package rca

import (
	"fmt"
	"strings"
	"time"

	"github.com/os2026/ebpf-rca/internal/detector"
	"github.com/os2026/ebpf-rca/internal/schema"
)

// 阻塞栈中出现这些符号片段，判定为锁/同步等待（而非纯 I/O 睡眠）。
var lockSymHints = []string{
	"futex", "mutex", "rwsem", "rt_mutex", "down_", "__lock", "semaphore", "rwlock",
}

// BuildLockReport 将一次锁竞争/长阻塞信号转换为结构化诊断报告。
// stack 为已符号化的阻塞内核栈（top-N），由 collector.ResolveStack 提供。
func BuildLockReport(sig detector.LockSignal, stack []string, offcpuThreshold float64) schema.AnomalyReport {
	s := sig.Sample
	isLock := stackHasLock(stack)
	stackStatus := "symbolized"
	if len(stack) == 0 {
		stackStatus = "unavailable"
	}
	root, suggestion, confidence := classifyLock(isLock, s.LastWaker, stackStatus)

	evidence := []schema.Evidence{
		{
			Type: "metric", Name: "offcpu_ratio",
			Value: round2(s.OffcpuRatio), Threshold: offcpuThreshold,
			Desc: "阻塞型 off-CPU 时间占墙钟比例",
		},
		{
			Type: "metric", Name: "max_offcpu_ms",
			Value: round2(s.MaxOffcpuMs),
			Desc:  "单次最长阻塞时长(毫秒)",
		},
		{
			Type: "event", Name: "block_count",
			Value: s.BlockCount,
			Desc:  "窗口内阻塞切出次数",
		},
		{
			Type: "event", Name: "last_waker_tid",
			Value: s.LastWaker,
			Desc:  "最近唤醒该线程者(唤醒链上游，疑似持锁方)",
		},
		{
			Type: "event", Name: "stack_status",
			Value: stackStatus,
			Desc:  "阻塞栈符号化状态",
		},
	}
	// 阻塞栈作为"线程堆栈聚集"证据逐帧入链。
	for i, fr := range stack {
		evidence = append(evidence, schema.Evidence{
			Type: "stack", Name: fmt.Sprintf("frame_%d", i), Func: fr,
			Desc: "阻塞点内核调用栈",
		})
	}

	anomalyType := "锁竞争"
	if !isLock {
		anomalyType = "长时间阻塞等待"
	}

	return schema.AnomalyReport{
		AnomalyType: anomalyType,
		RelatedObject: schema.RelatedObject{
			Pid:  s.Pid,
			Tid:  s.Pid,
			Comm: s.Comm,
		},
		KeyMetrics: map[string]interface{}{
			"offcpu_ratio":   round2(s.OffcpuRatio),
			"max_offcpu_ms":  round2(s.MaxOffcpuMs),
			"block_count":    s.BlockCount,
			"last_waker_tid": s.LastWaker,
			"stack_status":   stackStatus,
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

func stackHasLock(stack []string) bool {
	for _, fr := range stack {
		low := strings.ToLower(fr)
		for _, h := range lockSymHints {
			if strings.Contains(low, h) {
				return true
			}
		}
	}
	return false
}

func classifyLock(isLock bool, waker uint32, stackStatus string) (root, suggestion string, confidence float64) {
	if isLock {
		root = "多线程争用同一锁资源导致阻塞（off-CPU 等锁，疑似临界区过大或锁粒度过粗）"
		suggestion = fmt.Sprintf("缩小临界区/细化锁粒度，排查唤醒链上游持锁线程 tid=%d；可改用读写锁或无锁结构", waker)
		return root, suggestion, 0.9
	}
	if stackStatus != "symbolized" {
		return "线程长时间阻塞在内核等待，但当前无法符号化阻塞栈，不能确认其为锁竞争",
			"用 root 运行并确认 /proc/kallsyms 可读；再结合 I/O 与 syscall 场景确认阻塞来源",
			0.55
	}
	root = "线程长时间阻塞在内核等待（非计算型），疑似 I/O 或条件变量同步等待"
	suggestion = "结合 I/O 场景进一步确认阻塞来源；若为同步等待，检查唤醒时机与生产消费速率"
	return root, suggestion, 0.7
}
