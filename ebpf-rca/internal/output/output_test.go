package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

func TestMarkdownDeviceObject(t *testing.T) {
	var buf bytes.Buffer
	report := schema.AnomalyReport{
		AnomalyType: "I/O延迟抖动",
		RelatedObject: schema.RelatedObject{
			Device: "8:0 sda",
		},
		KeyMetrics:         map[string]interface{}{"p99_lat_ms": 25.0},
		SuspectedRootCause: "test",
		Suggestion:         "test",
	}
	if err := Write(&buf, report, "md"); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "device=8:0 sda") {
		t.Fatalf("markdown does not include device object: %q", got)
	}
	if strings.Contains(got, "pid=0") {
		t.Fatalf("markdown leaked empty pid: %q", got)
	}
}

func TestYAMLDocumentPrefix(t *testing.T) {
	var buf bytes.Buffer
	report := schema.AnomalyReport{
		AnomalyType:        "CPU异常占用",
		KeyMetrics:         map[string]interface{}{"cpu_util": 0.9},
		SuspectedRootCause: "test",
		Suggestion:         "test",
	}
	if err := Write(&buf, report, "yaml"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "---\n") {
		t.Fatalf("yaml stream should start with document prefix: %q", buf.String())
	}
	var decoded schema.AnomalyReport
	if err := yaml.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("yaml output is not parseable: %v", err)
	}
	if decoded.AnomalyType != report.AnomalyType {
		t.Fatalf("decoded anomaly_type = %q, want %q", decoded.AnomalyType, report.AnomalyType)
	}
}

func TestWriteJSONLIsOneCompactValidatedObject(t *testing.T) {
	var buf bytes.Buffer
	report := validJSONReport()
	if err := WriteJSONL(&buf, report); err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.TrimSpace(buf.String()), "\n") != 0 {
		t.Fatalf("jsonl report spans multiple lines: %q", buf.String())
	}
	var decoded schema.AnomalyReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestWriteSessionProducesSingleEnvelope(t *testing.T) {
	now := "2026-07-10T00:00:00Z"
	later := "2026-07-10T00:00:01Z"
	session := schema.DiagnosticSession{
		SchemaVersion: "1.0",
		StartedAt:     now, EndedAt: later, ElapsedMS: 1000,
		Environment: schema.RuntimeEnvironment{Hostname: "test", OS: "linux", Architecture: "amd64", KernelRelease: "6.6", BTF: true},
		Configuration: schema.SessionConfiguration{
			Scenario: "cpu", IntervalMS: 1000, Sustain: 1,
			Thresholds: map[string]float64{
				"cpu_util": 0.9, "io_p99_ms": 20, "mem_available_floor_pct": 15,
				"lock_offcpu_ratio": 0.3, "syscall_calls_per_sec": 10000,
			},
		},
		Collectors: []schema.CollectorStatus{{Name: "cpu", Requested: true, Initialized: true, State: "stopped", PollCount: 1,
			Health: &schema.CollectorHealth{MapMemoryBytes: 1, Counters: map[string]uint64{"map_update_fail": 0}}}},
		Reports: []schema.AnomalyReport{validJSONReport()},
	}
	var buf bytes.Buffer
	if err := WriteSession(&buf, session); err != nil {
		t.Fatal(err)
	}
	var decoded schema.DiagnosticSession
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Reports) != 1 || decoded.SchemaVersion != "1.0" {
		t.Fatalf("unexpected session: %+v", decoded)
	}
}

func validJSONReport() schema.AnomalyReport {
	return schema.AnomalyReport{
		AnomalyType:   "CPU异常占用",
		RootCauseCode: schema.RootCauseCPUComputeHotspot,
		RelatedObject: schema.RelatedObject{Pid: 1, Tid: 1, Comm: "test"},
		KeyMetrics:    map[string]interface{}{"cpu_util": 1.0},
		TimeWindow: schema.TimeWindow{
			Start: "2026-07-10T00:00:00Z", End: "2026-07-10T00:00:01Z", ElapsedMS: 1000,
		},
		SuspectedRootCause: "compute hotspot",
		Confidence:         0.9,
		EvidenceChain:      []schema.Evidence{{Type: "metric", Name: "cpu_util", Value: 1.0}},
		Suggestion:         "profile",
	}
}
