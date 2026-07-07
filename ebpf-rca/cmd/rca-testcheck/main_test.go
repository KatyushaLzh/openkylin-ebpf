package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func TestValidateGroundTruthThreadScenarios(t *testing.T) {
	truth := &groundTruth{
		Scenario:    "cpu",
		RootPID:     100,
		AllowedTIDs: []uint32{200, 201},
	}

	if errs := validateGroundTruth("cpu", schema.RelatedObject{Tid: 201}, truth); len(errs) != 0 {
		t.Fatalf("expected tid match to pass, got %v", errs)
	}
	if errs := validateGroundTruth("lock", schema.RelatedObject{Pid: 200}, truth); len(errs) != 0 {
		t.Fatalf("expected pid-as-tid compatibility to pass, got %v", errs)
	}
	if errs := validateGroundTruth("cpu", schema.RelatedObject{Tid: 999}, truth); len(errs) == 0 {
		t.Fatal("expected unrelated tid to fail")
	}
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
		Kind:                  "positive",
		ExpectedAnomalyTypes:  []string{"CPU异常占用"},
		RelatedObject:         "process",
		RequiredKeyMetrics:    []string{"cpu_util"},
		RequiredEvidenceNames: []string{"cpu_util"},
		NumericFloors:         map[string]float64{"cpu_util": 0.75},
	}
	truth := &groundTruth{
		Scenario:    "cpu",
		RootPID:     100,
		AllowedTIDs: []uint32{123},
	}

	wrong := validReport(schema.RelatedObject{Pid: 999, Tid: 999, Comm: "other"})
	path := writeReportsForTest(t, wrong)
	res := validatePositive("cpu", spec, path, truth)
	if len(res.Errors) == 0 {
		t.Fatal("expected report for unrelated process to fail")
	}

	right := validReport(schema.RelatedObject{Pid: 123, Tid: 123, Comm: "target"})
	path = writeReportsForTest(t, wrong, right)
	res = validatePositive("cpu", spec, path, truth)
	if len(res.Errors) != 0 {
		t.Fatalf("expected one report to match truth, got %v", res.Errors)
	}
	if res.MatchedObject.Tid != 123 {
		t.Fatalf("matched wrong object: %+v", res.MatchedObject)
	}
}

func TestValidatePositiveRecordsExtraReportsAsWarning(t *testing.T) {
	spec := scenarioSpec{
		Kind:                  "positive",
		ExpectedAnomalyTypes:  []string{"CPU异常占用"},
		RelatedObject:         "process",
		RequiredKeyMetrics:    []string{"cpu_util"},
		RequiredEvidenceNames: []string{"cpu_util"},
		NumericFloors:         map[string]float64{"cpu_util": 0.75},
	}
	truth := &groundTruth{
		Scenario:    "cpu",
		RootPID:     100,
		AllowedTIDs: []uint32{123},
	}

	right := validReport(schema.RelatedObject{Pid: 123, Tid: 123, Comm: "target"})
	extra := validReport(schema.RelatedObject{Pid: 999, Tid: 999, Comm: "other"})
	path := writeReportsForTest(t, right, extra)
	res := validatePositive("cpu", spec, path, truth)
	if len(res.Errors) != 0 {
		t.Fatalf("expected pass with warning, got errors %v", res.Errors)
	}
	if res.ExtraReportCount != 1 || len(res.Warnings) == 0 {
		t.Fatalf("expected one extra report warning, got extra=%d warnings=%v", res.ExtraReportCount, res.Warnings)
	}
}

func TestValidateReportStrictFields(t *testing.T) {
	spec := scenarioSpec{
		Kind:                  "positive",
		ExpectedAnomalyTypes:  []string{"CPU异常占用"},
		RelatedObject:         "process",
		RequiredKeyMetrics:    []string{"cpu_util"},
		RequiredEvidenceNames: []string{"cpu_util"},
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
		RelatedObject: obj,
		KeyMetrics: map[string]interface{}{
			"cpu_util": 0.9,
		},
		TimeWindow: schema.TimeWindow{
			Start: now.Format(time.RFC3339),
			End:   now.Add(time.Second).Format(time.RFC3339),
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
