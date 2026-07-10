package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func TestAggregatorCompactsLockReportsAndSyncsEvidence(t *testing.T) {
	agg := New()
	first := lockReport(100, 101, 0x1234, "stress-ng-futex", 0.7, 10, 3, "schedule", "futex_wait_queue")
	second := lockReport(100, 102, 0x1234, "stress-ng-futex", 0.9, 30, 4, "schedule", "futex_wait_queue")
	second.TimeWindow = schema.TimeWindow{Start: "2026-07-08T00:00:01Z", End: "2026-07-08T00:00:02Z"}
	agg.Add(first)
	agg.Add(second)

	reports := agg.Reports()
	if len(reports) != 1 {
		t.Fatalf("reports=%d, want 1", len(reports))
	}
	r := reports[0]
	if r.RelatedObject.Tid != 102 {
		t.Fatalf("representative tid=%d, want most severe tid 102", r.RelatedObject.Tid)
	}
	if got := r.KeyMetrics["offcpu_ratio"]; got != 0.9 {
		t.Fatalf("offcpu_ratio=%#v, want 0.9", got)
	}
	if got := r.KeyMetrics["total_wait_ms"]; got != 150.0 {
		t.Fatalf("total_wait_ms=%#v, want 150.0", got)
	}
	if got := r.KeyMetrics["p99_wait_ms"]; got != 15.0 {
		t.Fatalf("p99_wait_ms=%#v, want 15.0", got)
	}
	if got := r.KeyMetrics["max_wait_ms"]; got != 30.0 {
		t.Fatalf("max_wait_ms=%#v, want 30.0", got)
	}
	if got := r.KeyMetrics["block_count"]; got != 7.0 {
		t.Fatalf("block_count=%#v, want 7.0", got)
	}
	if got := r.KeyMetrics["suppressed_report_count"]; got != 1 {
		t.Fatalf("suppressed_report_count=%#v, want 1", got)
	}
	if got := r.KeyMetrics["affected_tid_count"]; got != 2 {
		t.Fatalf("affected_tid_count=%#v, want 2", got)
	}
	assertEvidenceMatchesMetric(t, r, "offcpu_ratio")
	assertEvidenceMatchesMetric(t, r, "total_wait_ms")
	assertEvidenceMatchesMetric(t, r, "p99_wait_ms")
	assertEvidenceMatchesMetric(t, r, "max_wait_ms")
	assertEvidenceMatchesMetric(t, r, "block_count")
}

func TestAggregatorSeparatesFutexLockAddresses(t *testing.T) {
	agg := New()
	agg.Add(lockReport(100, 101, 0x1234, "stress-ng-futex", 0.7, 10, 3, "schedule", "futex_wait_queue"))
	agg.Add(lockReport(100, 102, 0x5678, "stress-ng-futex", 0.9, 30, 4, "schedule", "futex_wait_queue"))

	if got := agg.Count(); got != 2 {
		t.Fatalf("different lock addresses merged: count=%d, want 2", got)
	}
}

func TestAggregatorGroupsKernelWaitByTGIDAndStackNotWaiterTID(t *testing.T) {
	agg := New()
	first := lockReport(100, 101, 0, "worker", 0.7, 10, 3, "schedule", "mutex_lock")
	first.AnomalyType = "内核同步等待"
	first.RootCauseCode = schema.RootCauseLockKernelSyncWait
	second := lockReport(100, 102, 0, "worker", 0.9, 30, 4, "schedule", "mutex_lock")
	second.AnomalyType = "内核同步等待"
	second.RootCauseCode = schema.RootCauseLockKernelSyncWait
	second.TimeWindow = schema.TimeWindow{Start: "2026-07-08T00:00:01Z", End: "2026-07-08T00:00:02Z"}
	agg.Add(first)
	agg.Add(second)

	third := lockReport(100, 103, 0, "worker", 0.8, 20, 2, "schedule", "rwsem_down_read")
	third.AnomalyType = "内核同步等待"
	third.RootCauseCode = schema.RootCauseLockKernelSyncWait
	third.TimeWindow = schema.TimeWindow{Start: "2026-07-08T00:00:02Z", End: "2026-07-08T00:00:03Z"}
	agg.Add(third)

	if got := agg.Count(); got != 2 {
		t.Fatalf("kernel wait grouping count=%d, want 2", got)
	}
	if got := agg.Reports()[0].KeyMetrics["affected_tid_count"]; got != 2 {
		t.Fatalf("same-stack affected_tid_count=%#v, want 2", got)
	}
}

func TestAggregatorUsesStackIDWhenKernelSymbolsUnavailable(t *testing.T) {
	agg := New()
	first := lockReport(100, 101, 0, "worker", 0.7, 10, 3)
	first.AnomalyType = "内核同步等待"
	first.RootCauseCode = schema.RootCauseLockKernelSyncWait
	first.KeyMetrics["stack_id"] = int32(7)
	second := lockReport(100, 102, 0, "worker", 0.8, 20, 4)
	second.AnomalyType = "内核同步等待"
	second.RootCauseCode = schema.RootCauseLockKernelSyncWait
	second.KeyMetrics["stack_id"] = int32(8)
	agg.Add(first)
	agg.Add(second)
	if got := agg.Count(); got != 2 {
		t.Fatalf("different unresolved stack IDs merged: count=%d, want 2", got)
	}
}

func TestAggregatorCompactsSyscallReportsByProcessAndSyscall(t *testing.T) {
	agg := New()
	agg.Add(syscallReport(200, "dd", "read", 1000, 10, 100))
	agg.Add(syscallReport(200, "dd", "read", 1500, 20, 200))
	agg.Add(syscallReport(200, "dd", "write", 500, 5, 50))

	reports := agg.Reports()
	if len(reports) != 2 {
		t.Fatalf("reports=%d, want 2", len(reports))
	}
	var read schema.AnomalyReport
	for _, r := range reports {
		if r.KeyMetrics["syscall"] == "read" {
			read = r
		}
	}
	if read.AnomalyType == "" {
		t.Fatal("missing read report")
	}
	if read.RelatedObject.Pid != 200 {
		t.Fatalf("pid=%d, want 200", read.RelatedObject.Pid)
	}
	if got := read.KeyMetrics["calls_per_sec"]; got != 1500.0 {
		t.Fatalf("calls_per_sec=%#v, want 1500.0", got)
	}
	if got := read.KeyMetrics["suppressed_report_count"]; got != 1 {
		t.Fatalf("suppressed_report_count=%#v, want 1", got)
	}
	assertEvidenceMatchesMetric(t, read, "calls_per_sec")
	assertEvidenceMatchesMetric(t, read, "total_ms_per_sec")
}

func TestAggregatorSeparatesGappedWindowsAndRootCauseChanges(t *testing.T) {
	agg := New()
	first := syscallReport(200, "dd", "read", 1000, 10, 100)
	first.RootCauseCode = schema.RootCauseSyscallHighFrequency
	second := first
	second.TimeWindow = schema.TimeWindow{Start: "2026-07-08T00:00:05Z", End: "2026-07-08T00:00:06Z"}
	agg.Add(first)
	agg.Add(second)
	if got := agg.Count(); got != 2 {
		t.Fatalf("gapped incidents merged: count=%d, want 2", got)
	}

	third := second
	third.TimeWindow = schema.TimeWindow{Start: "2026-07-08T00:00:06Z", End: "2026-07-08T00:00:07Z"}
	third.RootCauseCode = schema.RootCauseSyscallHighLatency
	agg.Add(third)
	if got := agg.Count(); got != 3 {
		t.Fatalf("different root causes merged: count=%d, want 3", got)
	}
}

func TestAggregatorMergesSubMillisecondCollectorBoundaryGap(t *testing.T) {
	agg := New()
	first := syscallReport(200, "dd", "read", 1000, 10, 100)
	second := first
	second.TimeWindow = schema.TimeWindow{
		Start: "2026-07-08T00:00:01.001Z", End: "2026-07-08T00:00:02.001Z",
	}
	agg.Add(first)
	agg.Add(second)
	if got := agg.Count(); got != 1 {
		t.Fatalf("adjacent sampled windows were split: count=%d, want 1", got)
	}
}

func TestRenderDoesNotCallUnhealthyCollectionClean(t *testing.T) {
	agg := New()
	var out bytes.Buffer
	status := schema.CollectorStatus{
		Name: "cpu", Requested: true, Initialized: true, State: "stopped", PollCount: 1,
		HealthError: "read health map failed",
	}
	if err := agg.RenderWithCollectors(&out, time.Second, []schema.CollectorStatus{status}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "read health map failed") || !strings.Contains(text, "诊断不完整") {
		t.Fatalf("health failure not surfaced in report:\n%s", text)
	}
	if strings.Contains(text, "未发现异常。") {
		t.Fatalf("unhealthy zero-report session was presented as clean:\n%s", text)
	}
}

func lockReport(pid, tid uint32, address uint64, comm string, ratio, maxMs, blocks float64, stack ...string) schema.AnomalyReport {
	totalMs := maxMs * blocks
	p99Ms := maxMs / 2
	evidence := []schema.Evidence{
		{Type: "metric", Name: "offcpu_ratio", Value: ratio},
		{Type: "metric", Name: "total_wait_ms", Value: totalMs},
		{Type: "metric", Name: "p99_wait_ms", Value: p99Ms},
		{Type: "metric", Name: "max_wait_ms", Value: maxMs},
		{Type: "event", Name: "waiter_count", Value: 1},
		{Type: "event", Name: "block_count", Value: blocks},
	}
	for i, frame := range stack {
		evidence = append(evidence, schema.Evidence{Type: "stack", Name: "frame", Func: frame, Value: i})
	}
	return schema.AnomalyReport{
		AnomalyType:   "futex锁竞争",
		RootCauseCode: schema.RootCauseLockFutexContention,
		RelatedObject: schema.RelatedObject{
			Pid:         pid,
			Tid:         tid,
			Comm:        comm,
			LockAddress: address,
		},
		KeyMetrics: map[string]interface{}{
			"lock_address":  address,
			"offcpu_ratio":  ratio,
			"total_wait_ms": totalMs,
			"p99_wait_ms":   p99Ms,
			"max_wait_ms":   maxMs,
			"waiter_count":  1,
			"block_count":   blocks,
		},
		TimeWindow: schema.TimeWindow{
			Start: "2026-07-08T00:00:00Z",
			End:   "2026-07-08T00:00:01Z",
		},
		Confidence:    ratio,
		EvidenceChain: evidence,
	}
}

func syscallReport(pid uint32, comm, name string, calls, avgUs, totalMs float64) schema.AnomalyReport {
	return schema.AnomalyReport{
		AnomalyType:   "系统调用热点",
		RootCauseCode: schema.RootCauseSyscallHighFrequency,
		RelatedObject: schema.RelatedObject{
			Pid:  pid,
			Comm: comm,
		},
		KeyMetrics: map[string]interface{}{
			"syscall":          name,
			"calls_per_sec":    calls,
			"avg_lat_us":       avgUs,
			"total_ms_per_sec": totalMs,
		},
		TimeWindow: schema.TimeWindow{
			Start: "2026-07-08T00:00:00Z",
			End:   "2026-07-08T00:00:01Z",
		},
		Confidence: 0.8,
		EvidenceChain: []schema.Evidence{
			{Type: "metric", Name: "syscall", Value: name},
			{Type: "metric", Name: "calls_per_sec", Value: calls},
			{Type: "metric", Name: "avg_lat_us", Value: avgUs},
			{Type: "metric", Name: "total_ms_per_sec", Value: totalMs},
		},
	}
}

func assertEvidenceMatchesMetric(t *testing.T, r schema.AnomalyReport, name string) {
	t.Helper()
	metric := r.KeyMetrics[name]
	for _, ev := range r.EvidenceChain {
		if ev.Name == name {
			if ev.Value != metric {
				t.Fatalf("evidence %s=%#v, want metric %#v", name, ev.Value, metric)
			}
			return
		}
	}
	t.Fatalf("missing evidence %s", name)
}
