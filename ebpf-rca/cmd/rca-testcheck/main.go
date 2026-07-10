// Command rca-testcheck validates ebpf-rca local E2E test artifacts.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

const (
	truthSampleCount = 5
	truthSampleDelay = 500 * time.Millisecond
)

type testSpec struct {
	Scenarios map[string]scenarioSpec `yaml:"scenarios"`
}

type scenarioSpec struct {
	Kind                   string             `yaml:"kind"`
	Description            string             `yaml:"description"`
	Oracle                 string             `yaml:"oracle"`
	ExpectedAnomalyTypes   []string           `yaml:"expected_anomaly_types"`
	ExpectedRootCauseCodes []string           `yaml:"expected_root_cause_codes"`
	RelatedObject          string             `yaml:"related_object"`
	RequiredKeyMetrics     []string           `yaml:"required_key_metrics"`
	RequiredEvidenceNames  []string           `yaml:"required_evidence_names"`
	NumericFloors          map[string]float64 `yaml:"numeric_floors"`
	MaxReports             int                `yaml:"max_reports"`
	MaxExtraReports        int                `yaml:"max_extra_reports"`
	MinReportCount         int                `yaml:"min_report_count"`
	RequiredContains       []string           `yaml:"required_contains"`
}

type checkResult struct {
	Scenario            string               `json:"scenario"`
	Kind                string               `json:"kind"`
	Passed              bool                 `json:"passed"`
	EvaluationValid     bool                 `json:"evaluation_valid"`
	ReportCount         int                  `json:"report_count"`
	TypeMatch           bool                 `json:"type_match"`
	RootCauseCodeMatch  bool                 `json:"root_cause_code_match"`
	WorkloadObjectMatch bool                 `json:"workload_object_match"`
	TruePositive        int                  `json:"true_positive"`
	TrueNegative        int                  `json:"true_negative"`
	FalsePositive       int                  `json:"false_positive"`
	FalseNegative       int                  `json:"false_negative"`
	TopReportIndex      int                  `json:"top_report_index,omitempty"`
	TopReport           *reportMatch         `json:"top_report,omitempty"`
	MatchedAnomalyType  string               `json:"matched_anomaly_type,omitempty"`
	MatchedObject       schema.RelatedObject `json:"matched_object,omitempty"`
	MatchedReports      []reportMatch        `json:"matched_reports,omitempty"`
	ExtraReportCount    int                  `json:"extra_report_count,omitempty"`
	ExtraReports        []reportMatch        `json:"extra_reports,omitempty"`
	TruthSummary        string               `json:"truth_summary,omitempty"`
	Warnings            []string             `json:"warnings,omitempty"`
	Errors              []string             `json:"errors,omitempty"`
}

type reportMatch struct {
	Index               int                  `json:"index"`
	AnomalyType         string               `json:"anomaly_type"`
	RootCauseCode       string               `json:"root_cause_code"`
	Confidence          float64              `json:"confidence"`
	Object              schema.RelatedObject `json:"object"`
	TypeMatch           bool                 `json:"type_match"`
	RootCauseCodeMatch  bool                 `json:"root_cause_code_match"`
	WorkloadObjectMatch bool                 `json:"workload_object_match"`
	FullMatch           bool                 `json:"full_match"`
	Errors              []string             `json:"errors,omitempty"`
}

type groundTruth struct {
	Scenario     string            `json:"scenario"`
	RootPID      uint32            `json:"root_pid"`
	LockAddress  uint64            `json:"lock_address,omitempty"`
	Syscall      string            `json:"syscall,omitempty"`
	PGID         uint32            `json:"pgid,omitempty"`
	Session      uint32            `json:"session,omitempty"`
	SampleStart  string            `json:"sample_start,omitempty"`
	SampleEnd    string            `json:"sample_end,omitempty"`
	AllowedTGIDs []uint32          `json:"allowed_tgids,omitempty"`
	AllowedTIDs  []uint32          `json:"allowed_tids,omitempty"`
	AllowedComms []string          `json:"allowed_comms,omitempty"`
	PIDStartTime map[uint32]uint64 `json:"pid_start_time,omitempty"`
	IOFile       string            `json:"io_file,omitempty"`
	IODevice     string            `json:"io_device,omitempty"`
}

type procInfo struct {
	ppid      uint32
	pgid      uint32
	session   uint32
	startTime uint64
	state     byte
	comm      string
}

type truthFlags []string

func (f *truthFlags) String() string { return strings.Join(*f, ",") }
func (f *truthFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	specPath := flag.String("spec", "tests/scenarios.yaml", "scenario spec yaml")
	scenarioName := flag.String("scenario", "", "scenario name in spec")
	inputPath := flag.String("input", "", "JSON stream produced by ebpf-rca --format json")
	reportPath := flag.String("report", "", "Markdown report produced by ebpf-rca --report")
	summaryPath := flag.String("summary", "", "optional JSON summary output")
	var truthInputs truthFlags
	flag.Var(&truthInputs, "truth", "ground truth json; repeatable, optionally scenario=path")
	writeTruthMode := flag.Bool("write-truth", false, "write ground truth json instead of validating reports")
	rootPID := flag.Uint("root-pid", 0, "root workload pid for --write-truth")
	ioFile := flag.String("io-file", "", "I/O workload file path for --write-truth")
	watchTruth := flag.Bool("watch", false, "with --write-truth, sample until root pid exits")
	watchTimeout := flag.Duration("watch-timeout", 0, "max duration for --write-truth --watch; 0 means no explicit timeout")
	requireSessionAll := flag.Bool("require-session-all", false, "require strict all-mode DiagnosticSession, product defaults, and clean collector health")
	flag.Parse()

	if *scenarioName == "" {
		fatal(checkResult{Passed: false, Errors: []string{"--scenario is required"}}, *summaryPath)
	}
	if *writeTruthMode {
		if len(truthInputs) != 1 {
			fatal(checkResult{Scenario: *scenarioName, Errors: []string{"--truth is required with --write-truth"}}, *summaryPath)
		}
		if *rootPID == 0 || *rootPID > uint(^uint32(0)) {
			fatal(checkResult{Scenario: *scenarioName, Errors: []string{"--root-pid must be a non-zero uint32 with --write-truth"}}, *summaryPath)
		}
		_, truthPath := splitTruthInput(truthInputs[0], *scenarioName)
		truth, err := buildGroundTruth(*scenarioName, uint32(*rootPID), *ioFile, *watchTruth, *watchTimeout)
		if err != nil {
			fatal(checkResult{Scenario: *scenarioName, Errors: []string{err.Error()}}, *summaryPath)
		}
		if err := writeGroundTruth(truthPath, truth); err != nil {
			fatal(checkResult{Scenario: *scenarioName, Errors: []string{"write truth: " + err.Error()}}, *summaryPath)
		}
		fmt.Printf("WROTE truth %s: %s\n", truthPath, truthSummary(truth))
		return
	}

	spec, err := loadScenario(*specPath, *scenarioName)
	if err != nil {
		fatal(checkResult{Scenario: *scenarioName, Passed: false, Errors: []string{err.Error()}}, *summaryPath)
	}
	truths, err := readGroundTruths(truthInputs, *scenarioName)
	if err != nil {
		fatal(checkResult{Scenario: *scenarioName, Kind: spec.Kind, Errors: []string{"read truth: " + err.Error()}}, *summaryPath)
	}

	res := checkResult{Scenario: *scenarioName, Kind: spec.Kind}
	switch spec.Kind {
	case "positive":
		truth := truthForScenario(truths, *scenarioName)
		res = validatePositive(*scenarioName, spec, *inputPath, truth, *requireSessionAll)
	case "negative":
		res = validateNegative(*scenarioName, spec, *inputPath, *requireSessionAll)
	case "report":
		res = validateMarkdownReport(*scenarioName, spec, *reportPath, truths)
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

func validatePositive(name string, spec scenarioSpec, input string, truth *groundTruth, requireSessionAll ...bool) checkResult {
	reports, err := readReports(input, requireSessionAll...)
	res := checkResult{Scenario: name, Kind: spec.Kind, ReportCount: len(reports)}
	if truth != nil {
		res.TruthSummary = truthSummary(*truth)
	}
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	if truth == nil {
		res.Errors = append(res.Errors, "independent workload ground truth is required")
		return res
	}
	res.EvaluationValid = true
	if len(reports) == 0 {
		res.FalseNegative = 1
		res.Errors = append(res.Errors, "no anomaly report emitted")
		return res
	}

	var candidateErrs []string
	topReportIndex := 0
	for i := 1; i < len(reports); i++ {
		if reports[i].Confidence > reports[topReportIndex].Confidence {
			topReportIndex = i
		}
	}
	for i, report := range reports {
		typeMatch := contains(spec.ExpectedAnomalyTypes, report.AnomalyType)
		codeMatch := contains(spec.ExpectedRootCauseCodes, report.RootCauseCode)
		objectErrs := validateWorkloadOracle(name, report, truth)
		objectMatch := len(objectErrs) == 0

		errs := validateReport(report, spec)
		errs = append(errs, objectErrs...)
		m := reportMatch{
			Index:               i + 1,
			AnomalyType:         report.AnomalyType,
			RootCauseCode:       report.RootCauseCode,
			Confidence:          report.Confidence,
			Object:              report.RelatedObject,
			TypeMatch:           typeMatch,
			RootCauseCodeMatch:  codeMatch,
			WorkloadObjectMatch: objectMatch,
			FullMatch:           len(errs) == 0,
			Errors:              errs,
		}
		if i == topReportIndex {
			res.TopReportIndex = i + 1
			res.TopReport = &m
			res.TypeMatch = typeMatch
			res.RootCauseCodeMatch = codeMatch
			res.WorkloadObjectMatch = objectMatch
		}
		if len(errs) == 0 {
			res.MatchedReports = append(res.MatchedReports, m)
			if res.MatchedAnomalyType == "" {
				res.MatchedAnomalyType = report.AnomalyType
				res.MatchedObject = report.RelatedObject
			}
			continue
		}
		res.ExtraReports = append(res.ExtraReports, m)
		candidateErrs = append(candidateErrs, fmt.Sprintf("report %d: %s", i+1, strings.Join(errs, "; ")))
	}
	res.ExtraReportCount = len(res.ExtraReports)
	res.FalsePositive = res.ExtraReportCount
	if len(res.MatchedReports) > 0 {
		res.TruePositive = 1
		if res.ExtraReportCount > 0 {
			res.Errors = append(res.Errors, fmt.Sprintf("%d extra report(s) did not match expected type, root_cause_code and workload oracle", res.ExtraReportCount))
		}
		return res
	}
	res.FalseNegative = 1
	res.Errors = append(res.Errors, "no report matched expected scenario")
	res.Errors = append(res.Errors, candidateErrs...)
	return res
}

func validateNegative(name string, spec scenarioSpec, input string, requireSessionAll ...bool) checkResult {
	reports, err := readReports(input, requireSessionAll...)
	res := checkResult{Scenario: name, Kind: spec.Kind, ReportCount: len(reports)}
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	res.EvaluationValid = true
	res.FalsePositive = len(reports)
	if len(reports) == 0 {
		res.TrueNegative = 1
	}
	maxReports := spec.MaxReports
	if len(reports) > maxReports {
		res.Errors = append(res.Errors, fmt.Sprintf("expected at most %d reports, got %d", maxReports, len(reports)))
	}
	return res
}

func validateMarkdownReport(name string, spec scenarioSpec, reportPath string, truths map[string]groundTruth) checkResult {
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
	for _, scenario := range sortedTruthScenarios(truths) {
		truth := truths[scenario]
		if truth.Scenario == "" {
			truth.Scenario = scenario
		}
		if err := validateMarkdownTruth(text, scenario, truth); err != nil {
			res.Errors = append(res.Errors, err.Error())
		} else {
			res.MatchedReports = append(res.MatchedReports, reportMatch{Index: len(res.MatchedReports) + 1, AnomalyType: expectedAnomalyType(scenario)})
		}
	}
	return res
}

func readReports(path string, requireSessionAll ...bool) ([]schema.AnomalyReport, error) {
	requireFormal := len(requireSessionAll) > 0 && requireSessionAll[0]
	var data []byte
	var err error
	if path == "" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty JSON input")
	}

	// A single top-level value is either the JSON session envelope or one report.
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err == nil {
		var extra json.RawMessage
		if err := dec.Decode(&extra); err == io.EOF {
			return decodeTopLevelReports(raw, requireFormal)
		}
	}
	if requireFormal {
		return nil, fmt.Errorf("formal accuracy input must be exactly one DiagnosticSession JSON value")
	}

	// Multiple values are accepted only as strict, one-object-per-line JSONL.
	var reports []schema.AnomalyReport
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		trimmed := bytes.TrimSpace(scanner.Bytes())
		if len(trimmed) == 0 {
			continue
		}
		report, err := decodeStrictReport(trimmed)
		if err != nil {
			return nil, fmt.Errorf("decode JSONL line %d: %w", line, err)
		}
		reports = append(reports, report)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read JSONL: %w", err)
	}
	if len(reports) == 0 {
		return nil, fmt.Errorf("JSONL contains no reports")
	}
	return reports, nil
}

func decodeTopLevelReports(data []byte, requireFormal bool) ([]schema.AnomalyReport, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("top-level JSON must be an object: %w", err)
	}
	if _, ok := fields["reports"]; ok {
		session, err := schema.DecodeDiagnosticSessionJSON(data)
		if err != nil {
			return nil, fmt.Errorf("decode DiagnosticSession: %w", err)
		}
		if requireFormal {
			if err := validateFormalAccuracySession(session); err != nil {
				return nil, fmt.Errorf("formal DiagnosticSession: %w", err)
			}
		}
		return session.Reports, nil
	}
	if requireFormal {
		return nil, fmt.Errorf("formal accuracy input must be a DiagnosticSession, not a standalone report")
	}
	report, err := decodeStrictReport(data)
	if err != nil {
		return nil, err
	}
	return []schema.AnomalyReport{report}, nil
}

func validateFormalAccuracySession(session schema.DiagnosticSession) error {
	if session.Configuration.Scenario != "all" || session.Configuration.AllowPartial || session.Partial {
		return fmt.Errorf("requires scenario=all, allow_partial=false, partial=false")
	}
	if session.Configuration.TargetPID != 0 {
		return fmt.Errorf("target_pid must be 0 for the primary accuracy operating point")
	}
	if session.Configuration.IntervalMS != 1000 || session.Configuration.Sustain != 3 {
		return fmt.Errorf("requires product defaults interval_ms=1000 and sustain=3")
	}
	defaults := map[string]float64{
		"cpu_util": 0.9, "io_p99_ms": 20, "mem_available_floor_pct": 15,
		"lock_offcpu_ratio": 0.3, "syscall_calls_per_sec": 10000,
	}
	if len(session.Configuration.Thresholds) != len(defaults) {
		return fmt.Errorf("threshold set must contain exactly the five product defaults")
	}
	for name, want := range defaults {
		if got := session.Configuration.Thresholds[name]; got != want {
			return fmt.Errorf("threshold %s=%v, want product default %v", name, got, want)
		}
	}
	if !session.Environment.BTF {
		return fmt.Errorf("runtime environment did not expose BTF")
	}
	expected := map[string]bool{"cpu": true, "io": true, "mem": true, "lock": true, "syscall": true}
	if len(session.Collectors) != len(expected) {
		return fmt.Errorf("expected five collector health records, got %d", len(session.Collectors))
	}
	for _, status := range session.Collectors {
		if !expected[status.Name] {
			return fmt.Errorf("unexpected collector %q", status.Name)
		}
		delete(expected, status.Name)
		if !status.Requested || !status.Initialized || status.State != "stopped" || status.PollCount == 0 {
			return fmt.Errorf("collector %s lifecycle is not a clean stopped run", status.Name)
		}
		if status.Error != "" || status.HealthError != "" {
			return fmt.Errorf("collector %s reported error=%q health_error=%q", status.Name, status.Error, status.HealthError)
		}
		if status.Health == nil || status.Health.Counters == nil {
			return fmt.Errorf("collector %s is missing a health snapshot/counters", status.Name)
		}
		if status.Health.MapMemoryBytes == 0 {
			return fmt.Errorf("collector %s reported zero map memory", status.Name)
		}
		requiredCounters := map[string][]string{
			"cpu": {"map_update_fail", "stack_capture_fail", "program_stats_unavailable", "map_memory_estimated"},
			"io": {"duplicate_issue", "completion_miss", "map_update_fail", "partial_completion", "io_error",
				"current_inflight", "average_queue_depth_milli", "program_stats_unavailable", "map_memory_estimated"},
			"mem": {"reclaim_start_update_fail", "reclaim_end_miss", "map_update_fail", "oom_update_fail",
				"target_update_fail", "map_memory_estimated"},
			"lock": {"futex_update_fail", "offcpu_update_fail", "map_update_fail", "stack_capture_fail",
				"target_update_fail", "map_memory_estimated"},
			"syscall": {"start_update_fail", "exit_miss", "map_update_fail", "target_update_fail", "map_memory_estimated"},
		}
		for _, name := range requiredCounters[status.Name] {
			if _, ok := status.Health.Counters[name]; !ok {
				return fmt.Errorf("collector %s health is missing counter %s", status.Name, name)
			}
		}
		for name, value := range status.Health.Counters {
			fatal := strings.HasSuffix(name, "update_fail") || strings.HasSuffix(name, "_miss") ||
				name == "program_stats_unavailable" || name == "current_inflight" || name == "io_error"
			if fatal && value != 0 {
				return fmt.Errorf("collector %s integrity counter %s=%d, want 0", status.Name, name, value)
			}
		}
	}
	if len(expected) != 0 {
		return fmt.Errorf("missing collector health records")
	}
	return nil
}

func decodeStrictReport(data []byte) (schema.AnomalyReport, error) {
	return schema.DecodeAnomalyReportJSON(data)
}

func buildGroundTruth(scenario string, rootPID uint32, ioFile string, watch bool, watchTimeout time.Duration) (groundTruth, error) {
	rootStartTime, err := readProcStartTime(rootPID)
	if err != nil {
		return groundTruth{}, fmt.Errorf("bind root pid %d process instance: %w", rootPID, err)
	}
	if rootStartTime == 0 {
		return groundTruth{}, fmt.Errorf("bind root pid %d process instance: zero starttime", rootPID)
	}
	truth := groundTruth{
		Scenario:     scenario,
		RootPID:      rootPID,
		IOFile:       ioFile,
		PIDStartTime: make(map[uint32]uint64),
	}
	tgids := make(map[uint32]bool)
	tids := make(map[uint32]bool)
	comms := make(map[string]bool)
	var ioErr error
	var sawRoot bool
	var sampleEnd time.Time
	sampleStart := time.Now().UTC()
	deadline := time.Time{}
	if watch && watchTimeout > 0 {
		deadline = time.Now().Add(watchTimeout)
	}

	for i := 0; ; i++ {
		rootAlive := false
		rootPresent := false
		rootIdentityReadable := false
		snap, err := readProcSnapshot()
		if err == nil {
			rootInfo, present := snap[rootPID]
			rootPresent = present
			rootIdentityReadable = present && rootInfo.startTime != 0
			rootAlive = processInstanceInSnapshot(rootPID, rootStartTime, snap)
			desc := map[uint32]bool{}
			if rootAlive {
				desc = collectDescendants(rootPID, snap)
			}
			if len(desc) > 0 {
				sawRoot = true
				if root, ok := snap[rootPID]; ok {
					truth.PGID = root.pgid
					truth.Session = root.session
				}
			} else if watch && sawRoot && (!rootPresent || (rootIdentityReadable && !rootAlive)) {
				break
			}
			for pid := range desc {
				tgids[pid] = true
				if info, ok := snap[pid]; ok {
					if info.comm != "" {
						comms[info.comm] = true
					}
					if info.startTime > 0 {
						truth.PIDStartTime[pid] = info.startTime
					}
				}
				taskIDs, err := readTaskIDs(pid)
				if err != nil {
					tids[pid] = true
					continue
				}
				for _, tid := range taskIDs {
					tids[tid] = true
					if startTime, err := readProcStartTime(tid); err == nil && startTime > 0 {
						truth.PIDStartTime[tid] = startTime
					}
					if comm := readProcComm(fmt.Sprintf("/proc/%d/task/%d/comm", pid, tid)); comm != "" {
						comms[comm] = true
					}
				}
			}
		}
		if scenario == "io" && truth.IODevice == "" {
			truth.IODevice, ioErr = statDevice(ioFile)
		}
		sampleEnd = time.Now().UTC()
		if !watch && i+1 >= truthSampleCount {
			break
		}
		if watch && !deadline.IsZero() && !time.Now().Before(deadline) {
			if err != nil {
				return truth, fmt.Errorf("truth watch deadline reached without a readable process snapshot: %w", err)
			}
			if rootPresent && !rootIdentityReadable {
				return truth, fmt.Errorf("truth watch deadline reached but root pid %d starttime was unreadable", rootPID)
			}
			if rootAlive {
				return truth, fmt.Errorf("truth watch timeout: root pid %d process instance starttime=%d is still alive", rootPID, rootStartTime)
			}
			break
		}
		sleepFor := truthSampleDelay
		if watch && !deadline.IsZero() {
			if remaining := time.Until(deadline); remaining < sleepFor {
				sleepFor = remaining
			}
		}
		if sleepFor > 0 {
			time.Sleep(sleepFor)
		}
	}

	truth.AllowedTGIDs = sortedUint32Keys(tgids)
	truth.AllowedTIDs = sortedUint32Keys(tids)
	truth.AllowedComms = sortedStringKeys(comms)
	truth.SampleStart = sampleStart.Format(time.RFC3339)
	truth.SampleEnd = sampleEnd.Format(time.RFC3339)
	if len(truth.PIDStartTime) == 0 {
		truth.PIDStartTime = nil
	}
	if len(truth.AllowedTGIDs) == 0 && len(truth.AllowedTIDs) == 0 {
		return truth, fmt.Errorf("no live workload process found under root pid %d", rootPID)
	}
	if scenario == "io" {
		if ioFile == "" {
			return truth, fmt.Errorf("--io-file is required for io ground truth")
		}
		if truth.IODevice == "" {
			if ioErr != nil {
				return truth, fmt.Errorf("stat io file %s: %w", ioFile, ioErr)
			}
			return truth, fmt.Errorf("stat io file %s: device unavailable", ioFile)
		}
	}
	return truth, nil
}

func processInstanceInSnapshot(root uint32, startTime uint64, snap map[uint32]procInfo) bool {
	info, ok := snap[root]
	return ok && startTime != 0 && info.startTime == startTime && info.state != 'Z'
}

func readProcSnapshot() (map[uint32]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]procInfo)
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		ppid, err := readProcPPID(pid)
		if err != nil {
			continue
		}
		info := procInfo{ppid: ppid}
		if pgid, session, startTime, state, comm, err := readProcStat(pid); err == nil {
			info.pgid = pgid
			info.session = session
			info.startTime = startTime
			info.state = state
			info.comm = comm
		}
		out[pid] = info
	}
	return out, nil
}

func readProcPPID(pid uint32) (uint32, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed PPid line for pid %d", pid)
		}
		ppid64, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(ppid64), nil
	}
	return 0, fmt.Errorf("PPid not found for pid %d", pid)
}

func readProcStat(pid uint32) (pgid, session uint32, startTime uint64, state byte, comm string, err error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, 0, 0, "", err
	}
	text := string(b)
	open := strings.IndexByte(text, '(')
	close := strings.LastIndexByte(text, ')')
	if open < 0 || close <= open {
		return 0, 0, 0, 0, "", fmt.Errorf("malformed stat for pid %d", pid)
	}
	comm = text[open+1 : close]
	rest := strings.Fields(strings.TrimSpace(text[close+1:]))
	// rest[0] is state(field3), rest[2] pgid(field5), rest[3] session(field6), rest[19] starttime(field22).
	if len(rest) < 20 {
		return 0, 0, 0, 0, comm, fmt.Errorf("stat for pid %d has too few fields", pid)
	}
	if len(rest[0]) != 1 {
		return 0, 0, 0, 0, comm, fmt.Errorf("stat for pid %d has malformed state", pid)
	}
	state = rest[0][0]
	pgid64, err := strconv.ParseUint(rest[2], 10, 32)
	if err != nil {
		return 0, 0, 0, 0, comm, err
	}
	session64, err := strconv.ParseUint(rest[3], 10, 32)
	if err != nil {
		return 0, 0, 0, 0, comm, err
	}
	startTime, err = strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return 0, 0, 0, 0, comm, err
	}
	return uint32(pgid64), uint32(session64), startTime, state, comm, nil
}

func readProcStartTime(pid uint32) (uint64, error) {
	_, _, startTime, _, _, err := readProcStat(pid)
	return startTime, err
}

func collectDescendants(root uint32, snap map[uint32]procInfo) map[uint32]bool {
	if _, ok := snap[root]; !ok {
		return map[uint32]bool{}
	}
	children := make(map[uint32][]uint32)
	for pid, info := range snap {
		children[info.ppid] = append(children[info.ppid], pid)
	}
	seen := map[uint32]bool{root: true}
	queue := []uint32{root}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, child := range children[pid] {
			if seen[child] {
				continue
			}
			seen[child] = true
			queue = append(queue, child)
		}
	}
	return seen
}

func readTaskIDs(pid uint32) ([]uint32, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		tid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		out = append(out, uint32(tid64))
	}
	return out, nil
}

func readProcComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func statDevice(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return "", err
	}
	dev := uint64(st.Dev)
	maj, min := unix.Major(dev), unix.Minor(dev)
	if parent := parentBlockDevice(maj, min); parent != "" {
		return parent, nil
	}
	return fmt.Sprintf("%d:%d", maj, min), nil
}

func parentBlockDevice(maj, min uint32) string {
	sysDev := fmt.Sprintf("/sys/dev/block/%d:%d", maj, min)
	resolved, err := filepath.EvalSymlinks(sysDev)
	if err != nil {
		return ""
	}
	if _, err := os.Stat(filepath.Join(resolved, "partition")); err != nil {
		return ""
	}
	parentDev, err := os.ReadFile(filepath.Join(filepath.Dir(resolved), "dev"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(parentDev))
}

func writeGroundTruth(path string, truth groundTruth) error {
	b, err := json.MarshalIndent(truth, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func readGroundTruth(path string) (groundTruth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return groundTruth{}, err
	}
	var truth groundTruth
	if err := json.Unmarshal(b, &truth); err != nil {
		return groundTruth{}, err
	}
	return truth, nil
}

func readGroundTruths(inputs []string, defaultScenario string) (map[string]groundTruth, error) {
	truths := make(map[string]groundTruth)
	for _, input := range inputs {
		scenario, path := splitTruthInput(input, defaultScenario)
		if path == "" {
			return nil, fmt.Errorf("empty truth path")
		}
		truth, err := readGroundTruth(path)
		if err != nil {
			return nil, err
		}
		if truth.Scenario != "" && truth.Scenario != scenario {
			return nil, fmt.Errorf("truth %s has scenario %q, expected %q", path, truth.Scenario, scenario)
		}
		if truth.Scenario == "" {
			truth.Scenario = scenario
		}
		truths[scenario] = truth
	}
	return truths, nil
}

func splitTruthInput(input, defaultScenario string) (scenario, path string) {
	if before, after, ok := strings.Cut(input, "="); ok && before != "" && after != "" {
		return before, after
	}
	return defaultScenario, input
}

func truthForScenario(truths map[string]groundTruth, scenario string) *groundTruth {
	if len(truths) == 0 {
		return nil
	}
	if truth, ok := truths[scenario]; ok {
		return &truth
	}
	if len(truths) == 1 {
		for _, truth := range truths {
			return &truth
		}
	}
	return nil
}

func sortedTruthScenarios(truths map[string]groundTruth) []string {
	scenarios := make([]string, 0, len(truths))
	for scenario := range truths {
		scenarios = append(scenarios, scenario)
	}
	sort.Strings(scenarios)
	return scenarios
}

func validateReport(r schema.AnomalyReport, spec scenarioSpec) []string {
	var errs []string
	if !contains(spec.ExpectedAnomalyTypes, r.AnomalyType) {
		errs = append(errs, fmt.Sprintf("anomaly_type %q not in %v", r.AnomalyType, spec.ExpectedAnomalyTypes))
	}
	if !contains(spec.ExpectedRootCauseCodes, r.RootCauseCode) {
		errs = append(errs, fmt.Sprintf("root_cause_code %q not in %v", r.RootCauseCode, spec.ExpectedRootCauseCodes))
	}
	if r.RootCauseCode == schema.RootCauseLockFutexContention && r.RelatedObject.LockAddress == 0 {
		errs = append(errs, "related_object.lock_address is required for lock.futex_contention")
	}
	if r.SuspectedRootCause == "" {
		errs = append(errs, "suspected_root_cause is empty")
	}
	if r.Suggestion == "" {
		errs = append(errs, "suggestion is empty")
	}
	if r.Confidence <= 0 {
		errs = append(errs, "confidence must be positive")
	} else if r.Confidence > 1 {
		errs = append(errs, "confidence must be <= 1")
	}
	if len(r.KeyMetrics) == 0 {
		errs = append(errs, "key_metrics is empty")
	}
	if len(r.EvidenceChain) == 0 {
		errs = append(errs, "evidence_chain is empty")
	}
	var windowStart, windowEnd time.Time
	if r.TimeWindow.Start == "" || r.TimeWindow.End == "" {
		errs = append(errs, "time_window start/end is empty")
	} else if t, err := time.Parse(time.RFC3339, r.TimeWindow.Start); err != nil {
		errs = append(errs, "time_window.start is not RFC3339")
	} else {
		windowStart = t
		if t, err := time.Parse(time.RFC3339, r.TimeWindow.End); err != nil {
			errs = append(errs, "time_window.end is not RFC3339")
		} else {
			windowEnd = t
			if !windowStart.Before(windowEnd) {
				errs = append(errs, "time_window.start must be before end")
			}
		}
	}

	errs = append(errs, validateRelatedObject(r.RelatedObject, spec.RelatedObject)...)
	for _, metric := range spec.RequiredKeyMetrics {
		if _, ok := r.KeyMetrics[metric]; !ok {
			errs = append(errs, "missing key metric: "+metric)
		} else {
			errs = append(errs, validateMetricValue(metric, r.KeyMetrics[metric])...)
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
	evidenceByName := make(map[string]schema.Evidence, len(r.EvidenceChain))
	for _, ev := range r.EvidenceChain {
		evidenceNames[ev.Name] = true
		if _, ok := evidenceByName[ev.Name]; !ok {
			evidenceByName[ev.Name] = ev
		}
	}
	for _, name := range spec.RequiredEvidenceNames {
		if !evidenceNames[name] {
			errs = append(errs, "missing evidence: "+name)
			continue
		}
		if metric, ok := r.KeyMetrics[name]; ok {
			if !valuesEquivalent(metric, evidenceByName[name].Value) {
				errs = append(errs, fmt.Sprintf("evidence %s value does not match key metric", name))
			}
		}
	}
	return errs
}

func validateMetricValue(name string, value interface{}) []string {
	switch name {
	case "syscall", "stack_status":
		if s, ok := value.(string); !ok || s == "" {
			return []string{"metric is not a non-empty string: " + name}
		}
		return nil
	}
	f, ok := asFloat64(value)
	if !ok {
		return []string{"metric is not numeric: " + name}
	}
	if f < 0 {
		return []string{"metric must be non-negative: " + name}
	}
	switch name {
	case "cpu_util":
		if f > 1024 {
			return []string{"cpu_util is implausibly high"}
		}
	case "offcpu_ratio":
		if f > 10 {
			return []string{"offcpu_ratio is implausibly high"}
		}
	case "mem_available_pct":
		if f > 100 {
			return []string{"mem_available_pct must be <= 100"}
		}
	}
	return nil
}

func valuesEquivalent(a, b interface{}) bool {
	if b == nil {
		return true
	}
	if af, ok := asFloat64(a); ok {
		if bf, ok := asFloat64(b); ok {
			d := af - bf
			if d < 0 {
				d = -d
			}
			return d < 1e-6
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func validateGroundTruth(scenario string, obj schema.RelatedObject, truth *groundTruth) []string {
	if truth == nil {
		return []string{"workload ground truth is required"}
	}
	switch scenario {
	case "cpu":
		if !truthAllowsPID(*truth, obj.Pid, false) {
			return []string{fmt.Sprintf("related_object.pid is not a workload TGID: object=%s truth=%s", objectSummary(obj), truthSummary(*truth))}
		}
		if obj.Tid != 0 && !truthAllowsPID(*truth, obj.Tid, true) {
			return []string{fmt.Sprintf("related_object.tid is not a workload TID: object=%s truth=%s", objectSummary(obj), truthSummary(*truth))}
		}
		return nil
	case "lock":
		var errs []string
		if !truthAllowsPID(*truth, obj.Pid, false) {
			errs = append(errs, fmt.Sprintf("related_object.pid is not a workload TGID: object=%s truth=%s", objectSummary(obj), truthSummary(*truth)))
		}
		if !truthAllowsPID(*truth, obj.Tid, true) {
			errs = append(errs, fmt.Sprintf("related_object.tid is not a workload TID: object=%s truth=%s", objectSummary(obj), truthSummary(*truth)))
		}
		if truth.LockAddress == 0 {
			errs = append(errs, "lock ground truth is missing the explicit futex address")
		} else if obj.LockAddress != truth.LockAddress {
			errs = append(errs, fmt.Sprintf("related_object.lock_address=0x%x, want workload futex 0x%x", obj.LockAddress, truth.LockAddress))
		}
		return errs
	case "mem", "syscall":
		if truthAllowsPID(*truth, obj.Pid, false) {
			return nil
		}
		return []string{fmt.Sprintf("related_object pid does not match workload tgids: object=%s truth=%s", objectSummary(obj), truthSummary(*truth))}
	case "io":
		if truth.IODevice != "" && (obj.Device == truth.IODevice || strings.HasPrefix(obj.Device, truth.IODevice+" ")) {
			return nil
		}
		return []string{fmt.Sprintf("related_object device does not match workload device: object=%s truth=%s", objectSummary(obj), truthSummary(*truth))}
	default:
		return nil
	}
}

func validateWorkloadOracle(scenario string, report schema.AnomalyReport, truth *groundTruth) []string {
	errs := validateGroundTruth(scenario, report.RelatedObject, truth)
	if scenario != "syscall" || truth == nil {
		return errs
	}
	if truth.Syscall == "" {
		return append(errs, "syscall ground truth is missing the injected syscall name")
	}
	got, ok := report.KeyMetrics["syscall"].(string)
	if !ok || got != truth.Syscall {
		errs = append(errs, fmt.Sprintf("key_metrics.syscall=%q, want injected syscall %q", got, truth.Syscall))
	}
	return errs
}

func validateMarkdownTruth(text, scenario string, truth groundTruth) error {
	anomalyType := expectedAnomalyType(scenario)
	if anomalyType == "" {
		return nil
	}
	if !strings.Contains(text, anomalyType) {
		return fmt.Errorf("markdown report missing anomaly type %q for truth %s", anomalyType, scenario)
	}
	for _, token := range markdownTruthTokens(scenario, truth) {
		if token != "" && strings.Contains(text, token) {
			return nil
		}
	}
	return fmt.Errorf("markdown report has %q but no object token matched truth %s: %s", anomalyType, scenario, truthSummary(truth))
}

func markdownTruthTokens(scenario string, truth groundTruth) []string {
	var tokens []string
	switch scenario {
	case "cpu", "lock":
		for _, tid := range truth.AllowedTIDs {
			tokens = append(tokens, fmt.Sprintf("pid=%d", tid), fmt.Sprintf("tid=%d", tid), fmt.Sprintf("(pid=%d)", tid))
		}
	case "mem", "syscall":
		for _, pid := range truth.AllowedTGIDs {
			tokens = append(tokens, fmt.Sprintf("pid=%d", pid), fmt.Sprintf("(pid=%d)", pid))
		}
	case "io":
		if truth.IODevice != "" {
			tokens = append(tokens, "设备 "+truth.IODevice, "device="+truth.IODevice, truth.IODevice+" ")
		}
	}
	return tokens
}

func expectedAnomalyType(scenario string) string {
	switch scenario {
	case "cpu":
		return "CPU异常占用"
	case "io":
		return "I/O延迟抖动"
	case "mem":
		return "内存回收压力"
	case "lock":
		return "futex锁竞争"
	case "syscall":
		return "系统调用热点"
	default:
		return ""
	}
}

func truthAllowsPID(truth groundTruth, pid uint32, threadMode bool) bool {
	if pid == 0 {
		return false
	}
	allowed := truth.AllowedTGIDs
	if threadMode {
		allowed = truth.AllowedTIDs
	}
	if !containsUint32(allowed, pid) {
		return false
	}
	if len(truth.PIDStartTime) == 0 {
		return true
	}
	want, ok := truth.PIDStartTime[pid]
	if !ok || want == 0 {
		return true
	}
	got, err := readProcStartTime(pid)
	if err != nil {
		return true
	}
	return got == want
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
	var value float64
	switch x := v.(type) {
	case float64:
		value = x
	case float32:
		value = float64(x)
	case int:
		value = float64(x)
	case int32:
		value = float64(x)
	case int64:
		value = float64(x)
	case uint:
		value = float64(x)
	case uint32:
		value = float64(x)
	case uint64:
		value = float64(x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0, false
		}
		value = f
	default:
		return 0, false
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
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

func containsUint32(list []uint32, value uint32) bool {
	if value == 0 {
		return false
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func sortedUint32Keys(m map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		if k != 0 {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedStringKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func objectSummary(obj schema.RelatedObject) string {
	var parts []string
	if obj.Pid != 0 {
		parts = append(parts, fmt.Sprintf("pid=%d", obj.Pid))
	}
	if obj.Tid != 0 {
		parts = append(parts, fmt.Sprintf("tid=%d", obj.Tid))
	}
	if obj.Comm != "" {
		parts = append(parts, "comm="+obj.Comm)
	}
	if obj.Device != "" {
		parts = append(parts, "device="+obj.Device)
	}
	if obj.LockAddress != 0 {
		parts = append(parts, fmt.Sprintf("lock_address=0x%x", obj.LockAddress))
	}
	if len(parts) == 0 {
		return "<empty>"
	}
	return strings.Join(parts, ",")
}

func truthSummary(truth groundTruth) string {
	parts := []string{
		fmt.Sprintf("root_pid=%d", truth.RootPID),
		"tgids=" + summarizeUint32s(truth.AllowedTGIDs),
		"tids=" + summarizeUint32s(truth.AllowedTIDs),
	}
	if len(truth.AllowedComms) > 0 {
		parts = append(parts, "comms="+summarizeStrings(truth.AllowedComms))
	}
	if truth.IODevice != "" {
		parts = append(parts, "io_device="+truth.IODevice)
	}
	if truth.LockAddress != 0 {
		parts = append(parts, fmt.Sprintf("lock_address=0x%x", truth.LockAddress))
	}
	if truth.Syscall != "" {
		parts = append(parts, "syscall="+truth.Syscall)
	}
	return strings.Join(parts, " ")
}

func summarizeUint32s(values []uint32) string {
	if len(values) == 0 {
		return "[]"
	}
	limit := len(values)
	if limit > 12 {
		limit = 12
	}
	parts := make([]string, 0, limit+1)
	for _, v := range values[:limit] {
		parts = append(parts, strconv.FormatUint(uint64(v), 10))
	}
	if len(values) > limit {
		parts = append(parts, fmt.Sprintf("...(+%d)", len(values)-limit))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func summarizeStrings(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	limit := len(values)
	if limit > 8 {
		limit = 8
	}
	parts := append([]string(nil), values[:limit]...)
	if len(values) > limit {
		parts = append(parts, fmt.Sprintf("...(+%d)", len(values)-limit))
	}
	return "[" + strings.Join(parts, ",") + "]"
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
		fmt.Printf("PASS %s (%s): %d report(s), TP=%d TN=%d FP=%d FN=%d", res.Scenario, res.Kind, res.ReportCount, res.TruePositive, res.TrueNegative, res.FalsePositive, res.FalseNegative)
		if res.MatchedAnomalyType != "" {
			fmt.Printf(", matched=%s", res.MatchedAnomalyType)
		}
		if res.ExtraReportCount > 0 {
			fmt.Printf(", extra=%d", res.ExtraReportCount)
		}
		fmt.Println()
		for _, warn := range res.Warnings {
			fmt.Println("  ! " + warn)
		}
		return
	}
	fmt.Printf("FAIL %s (%s): %d report(s), TP=%d TN=%d FP=%d FN=%d", res.Scenario, res.Kind, res.ReportCount, res.TruePositive, res.TrueNegative, res.FalsePositive, res.FalseNegative)
	if res.Kind == "positive" && res.EvaluationValid {
		fmt.Printf(", type=%t code=%t object=%t", res.TypeMatch, res.RootCauseCodeMatch, res.WorkloadObjectMatch)
	}
	fmt.Println()
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
