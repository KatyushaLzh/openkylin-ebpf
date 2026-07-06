package output

import (
	"bytes"
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
