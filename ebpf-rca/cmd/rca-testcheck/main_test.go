package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func TestValidateGroundTruthThreadScenarios(t *testing.T) {
	truth := &groundTruth{
		Scenario:     "cpu",
		RootPID:      100,
		LockAddress:  0x1234,
		AllowedTGIDs: []uint32{200},
		AllowedTIDs:  []uint32{200, 201},
	}

	if errs := validateGroundTruth("cpu", schema.RelatedObject{Pid: 200, Tid: 201}, truth); len(errs) != 0 {
		t.Fatalf("expected tid match to pass, got %v", errs)
	}
	if errs := validateGroundTruth("lock", schema.RelatedObject{Pid: 200, Tid: 201, LockAddress: 0x1234}, truth); len(errs) != 0 {
		t.Fatalf("expected workload futex instance to pass, got %v", errs)
	}
	if errs := validateGroundTruth("lock", schema.RelatedObject{Pid: 200, Tid: 201, LockAddress: 0x9999}, truth); len(errs) == 0 {
		t.Fatal("expected unrelated futex address to fail")
	}
	if errs := validateGroundTruth("cpu", schema.RelatedObject{Tid: 999}, truth); len(errs) == 0 {
		t.Fatal("expected unrelated tid to fail")
	}
}

func TestValidateLockFutexInstanceMatchingWrongAndExtra(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"futex锁竞争"},
		ExpectedRootCauseCodes: []string{schema.RootCauseLockFutexContention},
		RelatedObject:          "process",
	}
	truth := &groundTruth{
		Scenario:     "lock",
		RootPID:      100,
		LockAddress:  0x1234,
		AllowedTGIDs: []uint32{200},
		AllowedTIDs:  []uint32{201, 202},
	}
	report := func(address uint64) schema.AnomalyReport {
		result := validReport(schema.RelatedObject{
			Pid: 200, Tid: 201, Comm: "rca_lock_wait", LockAddress: address, Scope: "process",
		})
		result.AnomalyType = "futex锁竞争"
		result.RootCauseCode = schema.RootCauseLockFutexContention
		return result
	}

	t.Run("matching", func(t *testing.T) {
		res := validatePositive("lock", spec, writeReportsForTest(t, report(0x1234)), truth)
		if len(res.Errors) != 0 || res.TruePositive != 1 || res.FalsePositive != 0 || res.FalseNegative != 0 {
			t.Fatalf("matching futex instance did not produce one TP: %+v", res)
		}
	})
	t.Run("wrong-address", func(t *testing.T) {
		res := validatePositive("lock", spec, writeReportsForTest(t, report(0x9999)), truth)
		if !res.EvaluationValid || res.TruePositive != 0 || res.FalsePositive != 1 || res.FalseNegative != 1 {
			t.Fatalf("wrong futex address must be FP+FN, got %+v", res)
		}
		if res.WorkloadObjectMatch {
			t.Fatal("wrong futex address was accepted by the object oracle")
		}
	})
	t.Run("matching-plus-wrong-extra", func(t *testing.T) {
		res := validatePositive("lock", spec, writeReportsForTest(t, report(0x1234), report(0x9999)), truth)
		if res.TruePositive != 1 || res.FalsePositive != 1 || res.FalseNegative != 0 || res.ExtraReportCount != 1 {
			t.Fatalf("matching report plus wrong-address extra must be TP+FP, got %+v", res)
		}
	})
}

func TestProcessInstanceInSnapshotBindsStartTime(t *testing.T) {
	snapshot := map[uint32]procInfo{42: {startTime: 100, state: 'S'}}
	if !processInstanceInSnapshot(42, 100, snapshot) {
		t.Fatal("matching pid/starttime process instance was not found")
	}
	if processInstanceInSnapshot(42, 101, snapshot) {
		t.Fatal("PID reuse with a different starttime was accepted")
	}
	if processInstanceInSnapshot(43, 100, snapshot) {
		t.Fatal("missing root PID was accepted")
	}
	snapshot[42] = procInfo{startTime: 100, state: 'Z'}
	if processInstanceInSnapshot(42, 100, snapshot) {
		t.Fatal("zombie root was treated as a live process instance")
	}
}

func TestBuildGroundTruthFailsWhenWatchDeadlineLeavesRootAlive(t *testing.T) {
	cmd := exec.Command("sleep", "2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	_, err := buildGroundTruth("syscall", uint32(cmd.Process.Pid), "", true, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "truth watch timeout") {
		t.Fatalf("live root at watch deadline must fail, got %v", err)
	}
}

func TestBuildGroundTruthStopsOnUnreapedZombieRoot(t *testing.T) {
	cmd := exec.Command("sleep", "0.2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	truth, err := buildGroundTruth("syscall", uint32(cmd.Process.Pid), "", true, time.Second)
	if err != nil {
		t.Fatalf("unreaped zombie should terminate truth watch successfully: %v", err)
	}
	if len(truth.AllowedTGIDs) == 0 {
		t.Fatal("truth watcher did not capture the process before it became a zombie")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
}

func TestValidateGroundTruthProcessScenarios(t *testing.T) {
	truth := &groundTruth{
		Scenario:     "syscall",
		RootPID:      100,
		AllowedTGIDs: []uint32{300, 301},
	}

	if errs := validateGroundTruth("syscall", schema.RelatedObject{Pid: 301}, truth); len(errs) != 0 {
		t.Fatalf("expected syscall tgid match to pass, got %v", errs)
	}
	if errs := validateGroundTruth("mem", schema.RelatedObject{Pid: 300}, truth); len(errs) != 0 {
		t.Fatalf("expected mem tgid match to pass, got %v", errs)
	}
	if errs := validateGroundTruth("syscall", schema.RelatedObject{Pid: 999}, truth); len(errs) == 0 {
		t.Fatal("expected unrelated tgid to fail")
	}
}

func TestValidateSyscallWorkloadOracleRequiresExactName(t *testing.T) {
	truth := &groundTruth{Scenario: "syscall", AllowedTGIDs: []uint32{301}, Syscall: "read"}
	matching := schema.AnomalyReport{
		RelatedObject: schema.RelatedObject{Pid: 301},
		KeyMetrics:    map[string]interface{}{"syscall": "read"},
	}
	if errs := validateWorkloadOracle("syscall", matching, truth); len(errs) != 0 {
		t.Fatalf("matching syscall oracle failed: %v", errs)
	}
	wrong := matching
	wrong.KeyMetrics = map[string]interface{}{"syscall": "write"}
	if errs := validateWorkloadOracle("syscall", wrong, truth); len(errs) == 0 {
		t.Fatal("wrong syscall name unexpectedly matched the workload oracle")
	}
	missing := matching
	missing.KeyMetrics = map[string]interface{}{}
	if errs := validateWorkloadOracle("syscall", missing, truth); len(errs) == 0 {
		t.Fatal("missing syscall name unexpectedly matched the workload oracle")
	}
}

func TestValidateGroundTruthIOScenario(t *testing.T) {
	truth := &groundTruth{
		Scenario: "io",
		RootPID:  100,
		IODevice: "8:0",
	}

	if errs := validateGroundTruth("io", schema.RelatedObject{Device: "8:0 sda"}, truth); len(errs) != 0 {
		t.Fatalf("expected device prefix match to pass, got %v", errs)
	}
	if errs := validateGroundTruth("io", schema.RelatedObject{Device: "8:1 sda1"}, truth); len(errs) == 0 {
		t.Fatal("expected unrelated device to fail")
	}
}

func TestValidatePositiveRequiresGroundTruthMatch(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"CPU异常占用"},
		ExpectedRootCauseCodes: []string{schema.RootCauseCPUComputeHotspot},
		RelatedObject:          "process",
		RequiredKeyMetrics:     []string{"cpu_util"},
		RequiredEvidenceNames:  []string{"cpu_util"},
		NumericFloors:          map[string]float64{"cpu_util": 0.75},
	}
	truth := &groundTruth{
		Scenario:     "cpu",
		RootPID:      100,
		AllowedTGIDs: []uint32{123},
		AllowedTIDs:  []uint32{123},
	}

	wrong := validReport(schema.RelatedObject{Pid: 999, Tid: 999, Comm: "other"})
	path := writeReportsForTest(t, wrong)
	res := validatePositive("cpu", spec, path, truth)
	if len(res.Errors) == 0 {
		t.Fatal("expected report for unrelated process to fail")
	}
	if !res.EvaluationValid || !res.TypeMatch || !res.RootCauseCodeMatch || res.WorkloadObjectMatch {
		t.Fatalf("unexpected component matches for wrong object: %+v", res)
	}
	if res.TruePositive != 0 || res.FalseNegative != 1 || res.FalsePositive != 1 {
		t.Fatalf("wrong confusion counts for wrong object: TP=%d FP=%d FN=%d", res.TruePositive, res.FalsePositive, res.FalseNegative)
	}

	right := validReport(schema.RelatedObject{Pid: 123, Tid: 123, Comm: "target"})
	path = writeReportsForTest(t, right)
	res = validatePositive("cpu", spec, path, truth)
	if len(res.Errors) != 0 {
		t.Fatalf("expected one report to match truth, got %v", res.Errors)
	}
	if res.MatchedObject.Tid != 123 {
		t.Fatalf("matched wrong object: %+v", res.MatchedObject)
	}
	if !res.TypeMatch || !res.RootCauseCodeMatch || !res.WorkloadObjectMatch || res.TruePositive != 1 || res.FalseNegative != 0 || res.FalsePositive != 0 {
		t.Fatalf("wrong match dimensions for valid report: %+v", res)
	}
}

func TestValidatePositiveRejectsEveryExtraReport(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"CPU异常占用"},
		ExpectedRootCauseCodes: []string{schema.RootCauseCPUComputeHotspot},
		RelatedObject:          "process",
		RequiredKeyMetrics:     []string{"cpu_util"},
		RequiredEvidenceNames:  []string{"cpu_util"},
		NumericFloors:          map[string]float64{"cpu_util": 0.75},
	}
	truth := &groundTruth{
		Scenario:     "cpu",
		RootPID:      100,
		AllowedTGIDs: []uint32{123},
		AllowedTIDs:  []uint32{123},
	}

	right := validReport(schema.RelatedObject{Pid: 123, Tid: 123, Comm: "target"})
	extra := validReport(schema.RelatedObject{Pid: 999, Tid: 999, Comm: "other"})
	path := writeReportsForTest(t, right, extra)
	res := validatePositive("cpu", spec, path, truth)
	if len(res.Errors) == 0 {
		t.Fatal("expected extra report to fail strict oracle")
	}
	if res.ExtraReportCount != 1 {
		t.Fatalf("expected one extra report, got extra=%d", res.ExtraReportCount)
	}
	if res.TruePositive != 1 || res.FalsePositive != 1 || res.FalseNegative != 0 {
		t.Fatalf("TP and extra FP must coexist, got TP=%d FP=%d FN=%d", res.TruePositive, res.FalsePositive, res.FalseNegative)
	}
	if len(res.MatchedReports) != 1 || len(res.ExtraReports) != 1 || !res.MatchedReports[0].FullMatch || res.ExtraReports[0].FullMatch {
		t.Fatalf("unexpected per-report matches: matched=%+v extra=%+v", res.MatchedReports, res.ExtraReports)
	}
	if res.TopReportIndex != 1 || res.TopReport == nil || !res.TopReport.FullMatch {
		t.Fatalf("equal-confidence reports must keep the first report as Top-1: index=%d report=%+v", res.TopReportIndex, res.TopReport)
	}
}

func TestValidatePositiveRecordsTopReportMatchDimensions(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"CPU异常占用"},
		ExpectedRootCauseCodes: []string{schema.RootCauseCPUComputeHotspot},
		RelatedObject:          "process",
		RequiredKeyMetrics:     []string{"cpu_util"},
		RequiredEvidenceNames:  []string{"cpu_util"},
	}
	truth := &groundTruth{Scenario: "cpu", RootPID: 100, AllowedTGIDs: []uint32{123}, AllowedTIDs: []uint32{123}}

	wrongCode := validReport(schema.RelatedObject{Pid: 123, Tid: 123, Comm: "target"})
	wrongCode.RootCauseCode = schema.RootCauseCPUSchedulerPressure
	res := validatePositive("cpu", spec, writeReportsForTest(t, wrongCode), truth)
	if !res.TypeMatch || res.RootCauseCodeMatch || !res.WorkloadObjectMatch {
		t.Fatalf("expected type/object match but code mismatch, got %+v", res)
	}
	if res.TruePositive != 0 || res.FalsePositive != 1 || res.FalseNegative != 1 {
		t.Fatalf("wrong confusion counts: TP=%d FP=%d FN=%d", res.TruePositive, res.FalsePositive, res.FalseNegative)
	}

	wrongCode.Confidence = 0.95
	correct := validReport(schema.RelatedObject{Pid: 123, Tid: 123, Comm: "target"})
	res = validatePositive("cpu", spec, writeReportsForTest(t, wrongCode, correct), truth)
	if res.TopReportIndex != 1 || res.TopReport == nil || res.TopReport.RootCauseCodeMatch {
		t.Fatalf("highest-confidence first report must be the stable Top-1 candidate: %+v", res.TopReport)
	}
	if res.RootCauseCodeMatch {
		t.Fatal("lower-ranked correct code must not make Top-1 code accuracy pass")
	}
	if res.TruePositive != 1 || res.FalsePositive != 1 || res.FalseNegative != 0 {
		t.Fatalf("full TP must coexist with the Top-1 mismatch FP: TP=%d FP=%d FN=%d", res.TruePositive, res.FalsePositive, res.FalseNegative)
	}
}

func TestValidateNegativeCountsEveryReportAsFalsePositive(t *testing.T) {
	spec := scenarioSpec{Kind: "negative", MaxReports: 0}
	report := validReport(schema.RelatedObject{Pid: 1, Tid: 1, Comm: "noise"})
	res := validateNegative("idle_cpu", spec, writeReportsForTest(t, report, report))
	if !res.EvaluationValid || res.TrueNegative != 0 || res.FalsePositive != 2 {
		t.Fatalf("expected two report-level FPs, got %+v", res)
	}

	session := schema.DiagnosticSession{
		SchemaVersion: "1.0",
		StartedAt:     "2026-07-10T00:00:00Z", EndedAt: "2026-07-10T00:00:01Z", ElapsedMS: 1000,
		Environment:   schema.RuntimeEnvironment{Hostname: "test", OS: "linux", Architecture: "amd64", KernelRelease: "6.6", BTF: true},
		Configuration: schema.SessionConfiguration{Scenario: "all", IntervalMS: 1000, Sustain: 1, Thresholds: validThresholds()},
		Collectors:    terminalCollectors("cpu", "io", "mem", "lock", "syscall"),
		Reports:       []schema.AnomalyReport{},
	}
	b, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	res = validateNegative("idle_cpu", spec, writeTextForTest(t, string(b)))
	if len(res.Errors) != 0 || res.TrueNegative != 1 || res.FalsePositive != 0 {
		t.Fatalf("expected one TN for empty valid session, got %+v", res)
	}
}

func TestValidateReportStrictFields(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"CPU异常占用"},
		ExpectedRootCauseCodes: []string{schema.RootCauseCPUComputeHotspot},
		RelatedObject:          "process",
		RequiredKeyMetrics:     []string{"cpu_util"},
		RequiredEvidenceNames:  []string{"cpu_util"},
	}
	report := validReport(schema.RelatedObject{Pid: 1, Tid: 1, Comm: "target"})
	report.Confidence = 1.2
	report.TimeWindow.End = report.TimeWindow.Start
	report.EvidenceChain[0].Value = 0.1
	errs := validateReport(report, spec)
	if len(errs) < 3 {
		t.Fatalf("expected confidence/time/evidence errors, got %v", errs)
	}
}

func TestValidateReportRequiresFutexLockAddress(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"futex锁竞争"},
		ExpectedRootCauseCodes: []string{schema.RootCauseLockFutexContention},
		RelatedObject:          "process",
	}
	report := validReport(schema.RelatedObject{Pid: 1, Tid: 2, Comm: "target"})
	report.AnomalyType = "futex锁竞争"
	report.RootCauseCode = schema.RootCauseLockFutexContention
	if errs := validateReport(report, spec); len(errs) != 1 {
		t.Fatalf("expected exactly the missing futex-address error, got %v", errs)
	}
	report.RelatedObject.LockAddress = 0x1234
	if errs := validateReport(report, spec); len(errs) != 0 {
		t.Fatalf("expected futex report with lock address to pass, got %v", errs)
	}
}

func TestValidateReportRejectsNumericMetricEncodedAsString(t *testing.T) {
	spec := scenarioSpec{
		Kind:                   "positive",
		ExpectedAnomalyTypes:   []string{"CPU异常占用"},
		ExpectedRootCauseCodes: []string{schema.RootCauseCPUComputeHotspot},
		RelatedObject:          "process",
		RequiredKeyMetrics:     []string{"cpu_util"},
	}
	report := validReport(schema.RelatedObject{Pid: 1, Tid: 1, Comm: "target"})
	report.KeyMetrics["cpu_util"] = "0.9"
	if errs := validateReport(report, spec); len(errs) == 0 {
		t.Fatal("numeric oracle metrics must be JSON numbers, not numeric strings")
	}
}

func TestReadReportsAcceptsSessionAndRejectsDamagedJSONL(t *testing.T) {
	report := validReport(schema.RelatedObject{Pid: 1, Tid: 1, Comm: "target"})
	session := schema.DiagnosticSession{
		SchemaVersion: "1.0",
		StartedAt:     "2026-07-10T00:00:00Z", EndedAt: "2026-07-10T00:00:01Z", ElapsedMS: 1000,
		Environment:   schema.RuntimeEnvironment{Hostname: "test", OS: "linux", Architecture: "amd64", KernelRelease: "6.6", BTF: true},
		Configuration: schema.SessionConfiguration{Scenario: "cpu", IntervalMS: 1000, Sustain: 1, Thresholds: validThresholds()},
		Collectors:    terminalCollectors("cpu"),
		Reports:       []schema.AnomalyReport{report},
	}
	b, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTextForTest(t, string(b))
	reports, err := readReports(path)
	if err != nil || len(reports) != 1 {
		t.Fatalf("read session reports=%d err=%v", len(reports), err)
	}

	path = writeTextForTest(t, string(b)+"\nnot-json\n")
	if _, err := readReports(path); err == nil {
		t.Fatal("damaged JSONL must fail rather than skip text")
	}
}

func TestFormalAccuracySessionRequiresCleanCompleteHealth(t *testing.T) {
	session := formalSessionForTest()
	if err := validateFormalAccuracySession(session); err != nil {
		t.Fatalf("valid formal session: %v", err)
	}

	session.Collectors[0].HealthError = "cannot read health map"
	if err := validateFormalAccuracySession(session); err == nil {
		t.Fatal("health_error must invalidate formal accuracy evidence")
	}

	session = formalSessionForTest()
	session.Collectors[1].Health.Counters["completion_miss"] = 1
	if err := validateFormalAccuracySession(session); err == nil {
		t.Fatal("I/O data loss must invalidate formal accuracy evidence")
	}

	session = formalSessionForTest()
	delete(session.Collectors[4].Health.Counters, "map_update_fail")
	if err := validateFormalAccuracySession(session); err == nil {
		t.Fatal("missing integrity counter must invalidate formal accuracy evidence")
	}
}

func TestReadReportsFormalModeRejectsStandaloneReport(t *testing.T) {
	report := validReport(schema.RelatedObject{Pid: 1, Tid: 1, Comm: "target"})
	if _, err := readReports(writeReportsForTest(t, report), true); err == nil {
		t.Fatal("formal accuracy mode must require one all-mode DiagnosticSession")
	}
}

func TestValidateMarkdownReportRequiresAllTruths(t *testing.T) {
	spec := scenarioSpec{
		Kind:             "report",
		RequiredContains: []string{"# 系统异常诊断报告", "## 概要", "## 详细诊断"},
		MinReportCount:   2,
	}
	text := `# 系统异常诊断报告

- 发现异常：2 项

## 概要

| # | 异常类型 | 关联对象 | 疑似根因 | 置信度 |
| 1 | CPU异常占用 | rca_cpu_hot(pid=123) | hot | 0.90 |
| 2 | 系统调用热点 | rca_sys_hot(pid=456) | hot | 0.90 |

## 详细诊断

pid=123
pid=456
`
	path := writeTextForTest(t, text)
	res := validateMarkdownReport("report_all", spec, path, map[string]groundTruth{
		"cpu":     {Scenario: "cpu", AllowedTIDs: []uint32{123}},
		"syscall": {Scenario: "syscall", AllowedTGIDs: []uint32{456}},
	})
	if len(res.Errors) != 0 {
		t.Fatalf("expected report to match all truths, got %v", res.Errors)
	}

	res = validateMarkdownReport("report_all", spec, path, map[string]groundTruth{
		"cpu":     {Scenario: "cpu", AllowedTIDs: []uint32{123}},
		"syscall": {Scenario: "syscall", AllowedTGIDs: []uint32{999}},
	})
	if len(res.Errors) == 0 {
		t.Fatal("expected missing syscall truth object to fail")
	}
}

func validReport(obj schema.RelatedObject) schema.AnomalyReport {
	now := time.Unix(1700000000, 0).UTC()
	return schema.AnomalyReport{
		AnomalyType:   "CPU异常占用",
		RootCauseCode: schema.RootCauseCPUComputeHotspot,
		RelatedObject: obj,
		KeyMetrics: map[string]interface{}{
			"cpu_util": 0.9,
		},
		TimeWindow: schema.TimeWindow{
			Start:     now.Format(time.RFC3339),
			End:       now.Add(time.Second).Format(time.RFC3339),
			ElapsedMS: 1000,
		},
		SuspectedRootCause: "test root cause",
		Confidence:         0.9,
		EvidenceChain: []schema.Evidence{{
			Type:  "metric",
			Name:  "cpu_util",
			Value: 0.9,
		}},
		Suggestion: "test suggestion",
	}
}

func validThresholds() map[string]float64 {
	return map[string]float64{
		"cpu_util":                0.9,
		"io_p99_ms":               20,
		"mem_available_floor_pct": 15,
		"lock_offcpu_ratio":       0.5,
		"syscall_calls_per_sec":   10000,
	}
}

func terminalCollectors(names ...string) []schema.CollectorStatus {
	statuses := make([]schema.CollectorStatus, 0, len(names))
	for _, name := range names {
		statuses = append(statuses, schema.CollectorStatus{
			Name: name, Requested: true, Initialized: true, State: "stopped", PollCount: 1,
			Health: &schema.CollectorHealth{MapMemoryBytes: 1, Counters: map[string]uint64{"map_update_fail": 0}},
		})
	}
	return statuses
}

func formalSessionForTest() schema.DiagnosticSession {
	collectors := terminalCollectors("cpu", "io", "mem", "lock", "syscall")
	for i := range collectors {
		counters := map[string]uint64{"map_update_fail": 0, "map_memory_estimated": 0}
		switch collectors[i].Name {
		case "cpu":
			counters["program_stats_unavailable"] = 0
			counters["stack_capture_fail"] = 0
		case "io":
			counters["program_stats_unavailable"] = 0
			counters["completion_miss"] = 0
			counters["current_inflight"] = 0
			counters["io_error"] = 0
			counters["duplicate_issue"] = 0
			counters["partial_completion"] = 0
			counters["average_queue_depth_milli"] = 0
		case "mem":
			counters["reclaim_start_update_fail"] = 0
			counters["reclaim_end_miss"] = 0
			counters["oom_update_fail"] = 0
			counters["target_update_fail"] = 0
		case "lock":
			counters["futex_update_fail"] = 0
			counters["offcpu_update_fail"] = 0
			counters["stack_capture_fail"] = 0
			counters["target_update_fail"] = 0
		case "syscall":
			counters["start_update_fail"] = 0
			counters["exit_miss"] = 0
			counters["target_update_fail"] = 0
		}
		collectors[i].Health = &schema.CollectorHealth{MapMemoryBytes: 4096, Counters: counters}
	}
	return schema.DiagnosticSession{
		SchemaVersion: "1.0",
		StartedAt:     "2026-07-10T00:00:00Z",
		EndedAt:       "2026-07-10T00:00:01Z",
		ElapsedMS:     1000,
		Environment: schema.RuntimeEnvironment{
			Hostname: "test", OS: "linux", Architecture: "amd64", KernelRelease: "6.6", BTF: true,
		},
		Configuration: schema.SessionConfiguration{
			Scenario: "all", IntervalMS: 1000, Sustain: 3,
			Thresholds: map[string]float64{
				"cpu_util": 0.9, "io_p99_ms": 20, "mem_available_floor_pct": 15,
				"lock_offcpu_ratio": 0.3, "syscall_calls_per_sec": 10000,
			},
		},
		Collectors: collectors,
		Reports:    []schema.AnomalyReport{},
	}
}

func writeReportsForTest(t *testing.T, reports ...schema.AnomalyReport) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "reports-*.json")
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, report := range reports {
		if err := enc.Encode(report); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func writeTextForTest(t *testing.T, text string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "text-*.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}
