package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateDiagnosticSessionRequiresExactCollectorCoverage(t *testing.T) {
	s := validSessionForTest("all", "cpu", "io", "mem", "lock", "syscall")
	if err := ValidateDiagnosticSession(s); err != nil {
		t.Fatalf("valid all session: %v", err)
	}

	s.Collectors = s.Collectors[:4]
	if err := ValidateDiagnosticSession(s); err == nil || !strings.Contains(err.Error(), "coverage") {
		t.Fatalf("missing collector must fail coverage, got %v", err)
	}
}

func TestValidateDiagnosticSessionRejectsNonterminalAndPartialMismatch(t *testing.T) {
	s := validSessionForTest("cpu", "cpu")
	s.Collectors[0].State = "running"
	if err := ValidateDiagnosticSession(s); err == nil || !strings.Contains(err.Error(), "non-terminal") {
		t.Fatalf("running collector must fail, got %v", err)
	}

	s = validSessionForTest("cpu", "cpu")
	s.Collectors[0].State = "failed"
	s.Collectors[0].Error = "poll failed"
	if err := ValidateDiagnosticSession(s); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("failed collector with partial=false must fail, got %v", err)
	}
	s.Partial = true
	if err := ValidateDiagnosticSession(s); err != nil {
		t.Fatalf("consistent failed session: %v", err)
	}
}

func TestValidateDiagnosticSessionRejectsStoppedCollectorWithoutHealth(t *testing.T) {
	s := validSessionForTest("cpu", "cpu")
	s.Collectors[0].Health = nil
	if err := ValidateDiagnosticSession(s); err == nil || !strings.Contains(err.Error(), "health") {
		t.Fatalf("stopped collector without health must fail, got %v", err)
	}
}

func TestValidateDiagnosticSessionRejectsWrongScenarioReport(t *testing.T) {
	s := validSessionForTest("cpu", "cpu")
	report := validReportForTest()
	report.RootCauseCode = RootCauseSyscallHighFrequency
	report.RelatedObject = RelatedObject{Pid: 7, Scope: "process"}
	s.Reports = []AnomalyReport{report}
	if err := ValidateDiagnosticSession(s); err == nil || !strings.Contains(err.Error(), "does not match scenario") {
		t.Fatalf("cross-scenario report must fail, got %v", err)
	}
}

func TestValidateAnomalyReportRequiresFutexInstance(t *testing.T) {
	r := validReportForTest()
	r.RootCauseCode = RootCauseLockFutexContention
	r.AnomalyType = "futex锁竞争"
	if err := ValidateAnomalyReport(r); err == nil || !strings.Contains(err.Error(), "lock_address") {
		t.Fatalf("futex without address must fail, got %v", err)
	}
	r.RelatedObject.LockAddress = 0x1234
	if err := ValidateAnomalyReport(r); err != nil {
		t.Fatalf("futex instance report: %v", err)
	}
}

func TestDecodeAnomalyReportJSONRejectsMissingRequiredScalar(t *testing.T) {
	raw, err := json.Marshal(validReportForTest())
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "confidence")
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAnomalyReportJSON(raw); err == nil || !strings.Contains(err.Error(), "confidence") {
		t.Fatalf("missing confidence must fail, got %v", err)
	}
}

func TestDecodeAnomalyReportJSONRejectsDuplicateKeys(t *testing.T) {
	raw := mustMarshalJSON(t, validReportForTest())
	duplicated := strings.Replace(string(raw), `"confidence":0.9`, `"confidence":0.9,"confidence":0.8`, 1)
	if _, err := DecodeAnomalyReportJSON([]byte(duplicated)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate confidence must fail, got %v", err)
	}
}

func TestDecodeAnomalyReportJSONRejectsExplicitZeroOptionalIDs(t *testing.T) {
	var object map[string]interface{}
	if err := json.Unmarshal(mustMarshalJSON(t, validReportForTest()), &object); err != nil {
		t.Fatal(err)
	}
	related := object["related_object"].(map[string]interface{})
	related["pid"] = 0
	if _, err := DecodeAnomalyReportJSON(mustMarshalJSON(t, object)); err == nil || !strings.Contains(err.Error(), "pid") {
		t.Fatalf("explicit pid=0 must fail, got %v", err)
	}

	if err := json.Unmarshal(mustMarshalJSON(t, validReportForTest()), &object); err != nil {
		t.Fatal(err)
	}
	related = object["related_object"].(map[string]interface{})
	related["lock_address"] = 0
	if _, err := DecodeAnomalyReportJSON(mustMarshalJSON(t, object)); err == nil || !strings.Contains(err.Error(), "lock_address") {
		t.Fatalf("explicit lock_address=0 must fail, got %v", err)
	}
}

func TestDecodeAnomalyReportJSONRejectsExplicitEmptyOptionalString(t *testing.T) {
	var object map[string]interface{}
	if err := json.Unmarshal(mustMarshalJSON(t, validReportForTest()), &object); err != nil {
		t.Fatal(err)
	}
	related := object["related_object"].(map[string]interface{})
	related["device"] = ""
	if _, err := DecodeAnomalyReportJSON(mustMarshalJSON(t, object)); err == nil || !strings.Contains(err.Error(), "device") {
		t.Fatalf("explicit empty device must fail, got %v", err)
	}
}

func TestDecodeDiagnosticSessionJSONRejectsMissingRequiredBooleans(t *testing.T) {
	raw, err := json.Marshal(validSessionForTest("cpu", "cpu"))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "partial")
	raw, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDiagnosticSessionJSON(raw); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("missing partial must fail, got %v", err)
	}

	if err := json.Unmarshal(mustMarshalJSON(t, validSessionForTest("cpu", "cpu")), &object); err != nil {
		t.Fatal(err)
	}
	configuration := object["configuration"].(map[string]interface{})
	delete(configuration, "allow_partial")
	raw = mustMarshalJSON(t, object)
	if _, err := DecodeDiagnosticSessionJSON(raw); err == nil || !strings.Contains(err.Error(), "allow_partial") {
		t.Fatalf("missing allow_partial must fail, got %v", err)
	}
}

func TestDecodeDiagnosticSessionJSONRejectsExplicitZeroTargetPID(t *testing.T) {
	var object map[string]interface{}
	if err := json.Unmarshal(mustMarshalJSON(t, validSessionForTest("cpu", "cpu")), &object); err != nil {
		t.Fatal(err)
	}
	configuration := object["configuration"].(map[string]interface{})
	configuration["target_pid"] = 0
	if _, err := DecodeDiagnosticSessionJSON(mustMarshalJSON(t, object)); err == nil || !strings.Contains(err.Error(), "target_pid") {
		t.Fatalf("explicit target_pid=0 must fail, got %v", err)
	}
}

func TestDecodeDiagnosticSessionJSONRejectsExplicitEmptyCollectorMetadata(t *testing.T) {
	var object map[string]interface{}
	if err := json.Unmarshal(mustMarshalJSON(t, validSessionForTest("cpu", "cpu")), &object); err != nil {
		t.Fatal(err)
	}
	collector := object["collectors"].([]interface{})[0].(map[string]interface{})
	collector["last_poll_at"] = ""
	if _, err := DecodeDiagnosticSessionJSON(mustMarshalJSON(t, object)); err == nil || !strings.Contains(err.Error(), "last_poll_at") {
		t.Fatalf("explicit empty last_poll_at must fail, got %v", err)
	}
}

func mustMarshalJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validSessionForTest(scenario string, collectors ...string) DiagnosticSession {
	statuses := make([]CollectorStatus, 0, len(collectors))
	for _, name := range collectors {
		statuses = append(statuses, CollectorStatus{
			Name: name, Requested: true, Initialized: true, State: "stopped", PollCount: 1,
			Health: &CollectorHealth{MapMemoryBytes: 1, Counters: map[string]uint64{"map_update_fail": 0}},
		})
	}
	return DiagnosticSession{
		SchemaVersion: "1.0",
		StartedAt:     "2026-07-10T00:00:00Z",
		EndedAt:       "2026-07-10T00:00:01Z",
		ElapsedMS:     1000,
		Environment: RuntimeEnvironment{
			Hostname: "test", OS: "linux", Architecture: "amd64", KernelRelease: "6.6", BTF: true,
		},
		Configuration: SessionConfiguration{
			Scenario: scenario, IntervalMS: 1000, Sustain: 1,
			Thresholds: map[string]float64{
				"cpu_util": 0.9, "io_p99_ms": 20, "mem_available_floor_pct": 15,
				"lock_offcpu_ratio": 0.3, "syscall_calls_per_sec": 10000,
			},
		},
		Collectors: statuses,
		Reports:    []AnomalyReport{},
	}
}

func validReportForTest() AnomalyReport {
	return AnomalyReport{
		AnomalyType:   "CPU异常占用",
		RootCauseCode: RootCauseCPUComputeHotspot,
		RelatedObject: RelatedObject{Pid: 7, Tid: 8, Comm: "work", Scope: "process"},
		KeyMetrics:    map[string]interface{}{"cpu_util": 0.95},
		TimeWindow: TimeWindow{
			Start: "2026-07-10T00:00:00Z", End: "2026-07-10T00:00:01Z", ElapsedMS: 1000,
		},
		SuspectedRootCause: "compute hotspot",
		Confidence:         0.9,
		EvidenceChain:      []Evidence{{Type: "metric", Name: "cpu_util", Value: 0.95}},
		Suggestion:         "profile",
	}
}
