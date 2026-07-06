// Command rca-testcheck validates ebpf-rca local E2E test artifacts.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/os2026/ebpf-rca/internal/schema"
)

type testSpec struct {
	Scenarios map[string]scenarioSpec `yaml:"scenarios"`
}

type scenarioSpec struct {
	Kind                  string             `yaml:"kind"`
	Description           string             `yaml:"description"`
	ExpectedAnomalyTypes  []string           `yaml:"expected_anomaly_types"`
	RelatedObject         string             `yaml:"related_object"`
	RequiredKeyMetrics    []string           `yaml:"required_key_metrics"`
	RequiredEvidenceNames []string           `yaml:"required_evidence_names"`
	NumericFloors         map[string]float64 `yaml:"numeric_floors"`
	MaxReports            int                `yaml:"max_reports"`
	MinReportCount        int                `yaml:"min_report_count"`
	RequiredContains      []string           `yaml:"required_contains"`
}

type checkResult struct {
	Scenario           string               `json:"scenario"`
	Kind               string               `json:"kind"`
	Passed             bool                 `json:"passed"`
	ReportCount        int                  `json:"report_count"`
	MatchedAnomalyType string               `json:"matched_anomaly_type,omitempty"`
	MatchedObject      schema.RelatedObject `json:"matched_object,omitempty"`
	Errors             []string             `json:"errors,omitempty"`
}

func main() {
	specPath := flag.String("spec", "tests/scenarios.yaml", "scenario spec yaml")
	scenarioName := flag.String("scenario", "", "scenario name in spec")
	inputPath := flag.String("input", "", "JSON stream produced by ebpf-rca --format json")
	reportPath := flag.String("report", "", "Markdown report produced by ebpf-rca --report")
	summaryPath := flag.String("summary", "", "optional JSON summary output")
	flag.Parse()

	if *scenarioName == "" {
		fatal(checkResult{Passed: false, Errors: []string{"--scenario is required"}}, *summaryPath)
	}

	spec, err := loadScenario(*specPath, *scenarioName)
	if err != nil {
		fatal(checkResult{Scenario: *scenarioName, Passed: false, Errors: []string{err.Error()}}, *summaryPath)
	}

	res := checkResult{Scenario: *scenarioName, Kind: spec.Kind}
	switch spec.Kind {
	case "positive":
		res = validatePositive(*scenarioName, spec, *inputPath)
	case "negative":
		res = validateNegative(*scenarioName, spec, *inputPath)
	case "report":
		res = validateMarkdownReport(*scenarioName, spec, *reportPath)
	default:
		res.Errors = append(res.Errors, "unknown scenario kind: "+spec.Kind)
	}
	res.Passed = len(res.Errors) == 0

	if *summaryPath != "" {
		if err := writeSummary(*summaryPath, res); err != nil {
			res.Passed = false
			res.Errors = append(res.Errors, "write summary: "+err.Error())
		}
	}

	printHuman(res)
	if !res.Passed {
		os.Exit(1)
	}
}

func loadScenario(path, name string) (scenarioSpec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return scenarioSpec{}, err
	}
	var spec testSpec
	if err := yaml.Unmarshal(b, &spec); err != nil {
		return scenarioSpec{}, err
	}
	sc, ok := spec.Scenarios[name]
	if !ok {
		return scenarioSpec{}, fmt.Errorf("scenario %q not found in %s", name, path)
	}
	return sc, nil
}

func validatePositive(name string, spec scenarioSpec, input string) checkResult {
	reports, err := readReports(input)
	res := checkResult{Scenario: name, Kind: spec.Kind, ReportCount: len(reports)}
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	if len(reports) == 0 {
		res.Errors = append(res.Errors, "no anomaly report emitted")
		return res
	}

	var candidateErrs []string
	for i, report := range reports {
		errs := validateReport(report, spec)
		if len(errs) == 0 {
			res.MatchedAnomalyType = report.AnomalyType
			res.MatchedObject = report.RelatedObject
			return res
		}
		candidateErrs = append(candidateErrs, fmt.Sprintf("report %d: %s", i+1, strings.Join(errs, "; ")))
	}
	res.Errors = append(res.Errors, "no report matched expected scenario")
	res.Errors = append(res.Errors, candidateErrs...)
	return res
}

func validateNegative(name string, spec scenarioSpec, input string) checkResult {
	reports, err := readReports(input)
	res := checkResult{Scenario: name, Kind: spec.Kind, ReportCount: len(reports)}
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	maxReports := spec.MaxReports
	if len(reports) > maxReports {
		res.Errors = append(res.Errors, fmt.Sprintf("expected at most %d reports, got %d", maxReports, len(reports)))
	}
	return res
}

func validateMarkdownReport(name string, spec scenarioSpec, reportPath string) checkResult {
	res := checkResult{Scenario: name, Kind: spec.Kind}
	if reportPath == "" {
		res.Errors = append(res.Errors, "--report is required for report scenario")
		return res
	}
	b, err := os.ReadFile(reportPath)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	text := string(b)
	for _, want := range spec.RequiredContains {
		if !strings.Contains(text, want) {
			res.Errors = append(res.Errors, "markdown report missing required text: "+want)
		}
	}
	count, ok := extractReportCount(text)
	if ok {
		res.ReportCount = count
	} else if spec.MinReportCount > 0 {
		res.Errors = append(res.Errors, "could not parse report anomaly count")
	}
	if spec.MinReportCount > 0 && ok && count < spec.MinReportCount {
		res.Errors = append(res.Errors, fmt.Sprintf("expected at least %d reports, got %d", spec.MinReportCount, count))
	}
	return res
}

func readReports(path string) ([]schema.AnomalyReport, error) {
	var r io.Reader
	if path == "" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	dec := json.NewDecoder(r)
	dec.UseNumber()
	var reports []schema.AnomalyReport
	for {
		var report schema.AnomalyReport
		err := dec.Decode(&report)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode JSON report stream: %w", err)
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func validateReport(r schema.AnomalyReport, spec scenarioSpec) []string {
	var errs []string
	if !contains(spec.ExpectedAnomalyTypes, r.AnomalyType) {
		errs = append(errs, fmt.Sprintf("anomaly_type %q not in %v", r.AnomalyType, spec.ExpectedAnomalyTypes))
	}
	if r.SuspectedRootCause == "" {
		errs = append(errs, "suspected_root_cause is empty")
	}
	if r.Suggestion == "" {
		errs = append(errs, "suggestion is empty")
	}
	if r.Confidence <= 0 {
		errs = append(errs, "confidence must be positive")
	}
	if len(r.KeyMetrics) == 0 {
		errs = append(errs, "key_metrics is empty")
	}
	if len(r.EvidenceChain) == 0 {
		errs = append(errs, "evidence_chain is empty")
	}
	if r.TimeWindow.Start == "" || r.TimeWindow.End == "" {
		errs = append(errs, "time_window start/end is empty")
	} else if _, err := time.Parse(time.RFC3339, r.TimeWindow.Start); err != nil {
		errs = append(errs, "time_window.start is not RFC3339")
	} else if _, err := time.Parse(time.RFC3339, r.TimeWindow.End); err != nil {
		errs = append(errs, "time_window.end is not RFC3339")
	}

	errs = append(errs, validateRelatedObject(r.RelatedObject, spec.RelatedObject)...)
	for _, metric := range spec.RequiredKeyMetrics {
		if _, ok := r.KeyMetrics[metric]; !ok {
			errs = append(errs, "missing key metric: "+metric)
		}
	}
	for name, floor := range spec.NumericFloors {
		v, ok := r.KeyMetrics[name]
		if !ok {
			errs = append(errs, "missing numeric metric: "+name)
			continue
		}
		f, ok := asFloat64(v)
		if !ok {
			errs = append(errs, "metric is not numeric: "+name)
			continue
		}
		if f < floor {
			errs = append(errs, fmt.Sprintf("metric %s below floor %.4g: %.4g", name, floor, f))
		}
	}

	evidenceNames := make(map[string]bool, len(r.EvidenceChain))
	for _, ev := range r.EvidenceChain {
		evidenceNames[ev.Name] = true
	}
	for _, name := range spec.RequiredEvidenceNames {
		if !evidenceNames[name] {
			errs = append(errs, "missing evidence: "+name)
		}
	}
	return errs
}

func validateRelatedObject(obj schema.RelatedObject, want string) []string {
	switch want {
	case "", "any":
		return nil
	case "process":
		if obj.Pid == 0 && obj.Tid == 0 && obj.Comm == "" {
			return []string{"related_object has no process identity"}
		}
	case "device":
		if obj.Device == "" {
			return []string{"related_object.device is empty"}
		}
	default:
		return []string{"unknown related_object expectation: " + want}
	}
	return nil
}

func asFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func extractReportCount(text string) (int, bool) {
	re := regexp.MustCompile(`发现异常：([0-9]+) 项`)
	m := re.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func contains(list []string, value string) bool {
	if len(list) == 0 {
		return true
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func writeSummary(path string, res checkResult) error {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func printHuman(res checkResult) {
	if res.Passed {
		fmt.Printf("PASS %s (%s): %d report(s)", res.Scenario, res.Kind, res.ReportCount)
		if res.MatchedAnomalyType != "" {
			fmt.Printf(", matched=%s", res.MatchedAnomalyType)
		}
		fmt.Println()
		return
	}
	fmt.Printf("FAIL %s (%s): %d report(s)\n", res.Scenario, res.Kind, res.ReportCount)
	for _, err := range res.Errors {
		fmt.Println("  - " + err)
	}
}

func fatal(res checkResult, summaryPath string) {
	if summaryPath != "" {
		_ = writeSummary(summaryPath, res)
	}
	printHuman(res)
	os.Exit(1)
}
