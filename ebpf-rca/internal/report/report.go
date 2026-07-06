// Package report 将多场景的诊断结果汇总为一份结构化 Markdown 报告
// （赛题鼓励项：自动生成诊断报告 / 多维关联）。
package report

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/output"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

// Aggregator 收集去重后的诊断结果。
type Aggregator struct {
	reports []schema.AnomalyReport
	seen    map[string]bool
}

// New 构造聚合器。
func New() *Aggregator {
	return &Aggregator{seen: make(map[string]bool)}
}

// Add 添加一条结果（按异常类型+关联对象去重）。
func (a *Aggregator) Add(r schema.AnomalyReport) {
	k := fmt.Sprintf("%s|%d|%s|%s|%v",
		r.AnomalyType, r.RelatedObject.Pid, r.RelatedObject.Comm,
		r.RelatedObject.Device, r.KeyMetrics["syscall"])
	if a.seen[k] {
		return
	}
	a.seen[k] = true
	a.reports = append(a.reports, r)
}

// Count 返回已收集的结果数。
func (a *Aggregator) Count() int { return len(a.reports) }

// Render 输出一份汇总 Markdown 报告：概要表 + 各项详细诊断。
func (a *Aggregator) Render(w io.Writer, dur time.Duration) error {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "# 系统异常诊断报告\n\n")
	fmt.Fprintf(w, "- 主机：%s\n", host)
	fmt.Fprintf(w, "- 采集时长：%s\n", dur.Round(time.Second))
	fmt.Fprintf(w, "- 生成时间：%s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "- 发现异常：%d 项\n\n", len(a.reports))

	if len(a.reports) == 0 {
		fmt.Fprintf(w, "未发现异常。系统在采集窗口内各项指标均低于告警阈值。\n")
		return nil
	}

	fmt.Fprintf(w, "## 概要\n\n")
	fmt.Fprintf(w, "| # | 异常类型 | 关联对象 | 疑似根因 | 置信度 |\n")
	fmt.Fprintf(w, "|---|----------|----------|----------|--------|\n")
	for i, r := range a.reports {
		fmt.Fprintf(w, "| %d | %s | %s | %s | %.2f |\n",
			i+1, r.AnomalyType, objStr(r.RelatedObject), r.SuspectedRootCause, r.Confidence)
	}
	fmt.Fprintf(w, "\n## 详细诊断\n\n")
	for i, r := range a.reports {
		fmt.Fprintf(w, "### %d. %s\n\n", i+1, r.AnomalyType)
		if err := output.Write(w, r, "md"); err != nil {
			return err
		}
	}
	return nil
}

func objStr(o schema.RelatedObject) string {
	if o.Device != "" {
		return "设备 " + o.Device
	}
	if o.Comm != "" {
		return fmt.Sprintf("%s(pid=%d)", o.Comm, o.Pid)
	}
	return fmt.Sprintf("pid=%d", o.Pid)
}
