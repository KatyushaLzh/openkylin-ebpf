// Package output 将诊断报告渲染为 JSON / YAML / Markdown。
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/os2026/ebpf-rca/internal/schema"
)

// Write 按指定格式输出一份报告。
func Write(w io.Writer, r schema.AnomalyReport, format string) error {
	switch strings.ToLower(format) {
	case "", "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "yaml", "yml":
		b, err := yaml.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(w, "---\n"); err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	case "md", "markdown":
		return writeMarkdown(w, r)
	default:
		return fmt.Errorf("unknown format: %s", format)
	}
}

func writeMarkdown(w io.Writer, r schema.AnomalyReport) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## 诊断报告：%s\n\n", r.AnomalyType)
	fmt.Fprintf(&b, "- **关联对象**: %s\n", relatedObjectString(r.RelatedObject))
	fmt.Fprintf(&b, "- **时间窗口**: %s ~ %s\n", r.TimeWindow.Start, r.TimeWindow.End)
	fmt.Fprintf(&b, "- **疑似根因**: %s（置信度 %.2f）\n", r.SuspectedRootCause, r.Confidence)
	fmt.Fprintf(&b, "- **建议**: %s\n\n", r.Suggestion)

	b.WriteString("**关键指标**:\n\n")
	for k, v := range r.KeyMetrics {
		fmt.Fprintf(&b, "  - %s: %v\n", k, v)
	}

	b.WriteString("\n**证据链**:\n\n")
	for i, e := range r.EvidenceChain {
		fmt.Fprintf(&b, "  %d. [%s] %s = %v", i+1, e.Type, e.Name, e.Value)
		if e.Threshold != nil {
			fmt.Fprintf(&b, "（阈值 %v）", e.Threshold)
		}
		if e.Func != "" {
			fmt.Fprintf(&b, " @ %s", e.Func)
		}
		if e.Desc != "" {
			fmt.Fprintf(&b, " — %s", e.Desc)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n---\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func relatedObjectString(o schema.RelatedObject) string {
	if o.Device != "" {
		return "device=" + o.Device
	}
	parts := make([]string, 0, 3)
	if o.Pid != 0 {
		parts = append(parts, fmt.Sprintf("pid=%d", o.Pid))
	}
	if o.Tid != 0 {
		parts = append(parts, fmt.Sprintf("tid=%d", o.Tid))
	}
	if o.Comm != "" {
		parts = append(parts, "comm="+o.Comm)
	}
	if len(parts) == 0 {
		return "system"
	}
	return strings.Join(parts, " ")
}
