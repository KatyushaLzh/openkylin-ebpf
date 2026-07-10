package rca

import (
	"fmt"
	"strings"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/detector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

var lockSymHints = []string{
	"futex", "mutex", "rwsem", "rt_mutex", "down_", "__lock", "semaphore", "rwlock",
	"flock", "locks_", "filelock", "posix_lock",
}

func BuildLockReport(sig detector.LockSignal, stack []string, offcpuThreshold float64) schema.AnomalyReport {
	sample := sig.Sample
	stackStatus := "symbolized"
	if len(stack) == 0 {
		stackStatus = "unavailable"
	}
	root, suggestion, confidence := classifyLock(sample.Futex, StackHasLock(stack), sample.LastWaker, stackStatus)
	code := schema.RootCauseLockKernelSyncWait
	anomalyType := "内核同步等待"
	if sample.Futex {
		code = schema.RootCauseLockFutexContention
		anomalyType = "futex锁竞争"
	}
	scope := "process"
	if sample.Targeted {
		scope = "target_tree"
	}

	evidence := []schema.Evidence{
		{Type: "metric", Name: "offcpu_ratio", Value: round2(sample.OffcpuRatio), Threshold: offcpuThreshold,
			Desc: "该锁实例所有等待线程的阻塞线程时间/窗口墙钟时间；多线程时可大于 1"},
		{Type: "metric", Name: "total_wait_ms", Value: round2(sample.TotalWaitMs),
			Desc: "窗口内该锁实例的累计等待线程时间"},
		{Type: "metric", Name: "p99_wait_ms", Value: round2(sample.P99OffcpuMs),
			Desc: "按 log2 bucket 上界估算的 P99 单次等待"},
		{Type: "metric", Name: "max_wait_ms", Value: round2(sample.MaxOffcpuMs),
			Desc: "按 log2 bucket 上界估算的最长单次等待"},
		{Type: "event", Name: "waiter_count", Value: sample.WaiterCount,
			Desc: "窗口内出现等待的不同 TID 数"},
		{Type: "event", Name: "block_count", Value: sample.BlockCount,
			Desc: "窗口内自愿阻塞切出次数；已通过 typed sched_switch preempt 参数排除抢占"},
		{Type: "event", Name: "waker_tid", Value: sample.LastWaker,
			Desc: "最近唤醒等待线程的 TID；它是唤醒者，不等价于持锁者"},
		{Type: "event", Name: "futex_op", Value: sample.FutexOp,
			Desc: "do_futex fentry 捕获的 futex 操作；无地址的内核等待为 UINT32_MAX"},
		{Type: "event", Name: "top_waiters", Value: sample.TopWaiters,
			Desc: "按窗口累计等待时间排序的 Top 等待线程"},
		{Type: "event", Name: "stack_status", Value: stackStatus, Desc: "阻塞栈符号化状态"},
		{Type: "event", Name: "stack_id", Value: sample.StackID, Desc: "内核栈 map ID；符号不可用时仍用于区分等待路径"},
	}
	for i, frame := range stack {
		evidence = append(evidence, schema.Evidence{
			Type: "stack", Name: fmt.Sprintf("frame_%d", i), Func: frame, Desc: "阻塞点内核调用栈",
		})
	}

	return schema.AnomalyReport{
		AnomalyType:   anomalyType,
		RootCauseCode: code,
		RelatedObject: schema.RelatedObject{
			Pid:         sample.Pid,
			Tid:         sample.Tid,
			Comm:        sample.Comm,
			LockAddress: sample.LockAddress,
			Scope:       scope,
		},
		KeyMetrics: map[string]interface{}{
			"lock_address":  sample.LockAddress,
			"futex_op":      sample.FutexOp,
			"offcpu_ratio":  round2(sample.OffcpuRatio),
			"total_wait_ms": round2(sample.TotalWaitMs),
			"p99_wait_ms":   round2(sample.P99OffcpuMs),
			"max_wait_ms":   round2(sample.MaxOffcpuMs),
			"waiter_count":  sample.WaiterCount,
			"block_count":   sample.BlockCount,
			"waker_tid":     sample.LastWaker,
			"top_waiters":   sample.TopWaiters,
			"stack_status":  stackStatus,
			"stack_id":      sample.StackID,
		},
		TimeWindow:         timeWindow(sig.Window),
		SuspectedRootCause: root,
		Confidence:         confidence,
		EvidenceChain:      evidence,
		Suggestion:         suggestion,
	}
}

func StackHasLock(stack []string) bool {
	for _, frame := range stack {
		lower := strings.ToLower(frame)
		for _, hint := range lockSymHints {
			if strings.Contains(lower, hint) {
				return true
			}
		}
	}
	return false
}

func classifyLock(futex, stackHasLock bool, waker uint32, stackStatus string) (root, suggestion string, confidence float64) {
	if futex {
		return "多个线程在同一进程内等待同一 futex 地址，形成用户态锁实例竞争",
			fmt.Sprintf("按 lock_address 聚合调用栈与 Top waiters，缩短临界区或细化锁粒度；tid=%d 仅是最近唤醒者，不能据此断言其持锁", waker),
			0.95
	}
	if stackHasLock {
		return "线程在同一内核同步阻塞栈上聚集；该等待没有可用的用户态 futex 地址",
			"根据阻塞栈定位 mutex/rwsem/flock 等同步对象，缩短持有区间并检查锁顺序",
			0.88
	}
	if stackStatus != "symbolized" {
		return "观察到长时间自愿阻塞，但栈无法符号化且没有 futex 地址，不能断言具体锁实例",
			"确认 /proc/kallsyms 可读并复测；同时结合 I/O 与 syscall 报告区分同步等待和普通 I/O 睡眠",
			0.5
	}
	return "线程在非 futex 的内核等待路径长时间阻塞，现有栈证据不足以定位具体同步对象",
		"结合完整内核栈与相邻 I/O/syscall 报告确认等待来源，不要把唤醒者当作持锁者",
		0.62
}
