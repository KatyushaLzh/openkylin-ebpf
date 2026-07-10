// Package report 将多场景的诊断结果汇总为一份结构化 Markdown 报告
// （赛题鼓励项：自动生成诊断报告 / 多维关联）。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/output"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

// Aggregator 收集去重后的诊断结果。
type Aggregator struct {
	reports  []schema.AnomalyReport
	entries  map[string]int
	counts   map[string]int
	affected map[string]map[uint32]struct{}
}

// New 构造聚合器。
func New() *Aggregator {
	return &Aggregator{
		entries:  make(map[string]int),
		counts:   make(map[string]int),
		affected: make(map[string]map[uint32]struct{}),
	}
}

// Add 添加一条结果，并对报告展示中容易洪泛的 lock/syscall 场景做聚合。
func (a *Aggregator) Add(r schema.AnomalyReport) {
	k := aggregateKey(r)
	idx, ok := a.entries[k]
	if !ok || !windowsTouch(a.reports[idx].TimeWindow, r.TimeWindow) {
		a.entries[k] = len(a.reports)
		a.counts[k] = 1
		a.affected[k] = make(map[uint32]struct{})
		addAffected(a.affected[k], r)
		setAggregationMetrics(&r, a.counts[k], a.affected[k])
		a.reports = append(a.reports, r)
		return
	}
	a.counts[k]++
	addAffected(a.affected[k], r)
	merged := mergeReport(a.reports[idx], r)
	setAggregationMetrics(&merged, a.counts[k], a.affected[k])
	a.reports[idx] = merged
}

// Count 返回已收集的结果数。
func (a *Aggregator) Count() int { return len(a.reports) }

// Reports 返回聚合后的结构化诊断结果。
func (a *Aggregator) Reports() []schema.AnomalyReport {
	out := make([]schema.AnomalyReport, len(a.reports))
	copy(out, a.reports)
	return out
}

// Render 输出一份汇总 Markdown 报告：概要表 + 各项详细诊断。
func (a *Aggregator) Render(w io.Writer, dur time.Duration) error {
	return a.RenderWithCollectors(w, dur, nil)
}

// RenderWithCollectors renders collector lifecycle state so partial collection
// can never be presented as a clean "no anomaly" result.
func (a *Aggregator) RenderWithCollectors(w io.Writer, dur time.Duration, collectors []schema.CollectorStatus) error {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "# 系统异常诊断报告\n\n")
	fmt.Fprintf(w, "- 主机：%s\n", host)
	fmt.Fprintf(w, "- 采集时长：%s\n", dur.Round(time.Second))
	fmt.Fprintf(w, "- 生成时间：%s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "- 发现异常：%d 项\n\n", len(a.reports))
	failed := false
	if len(collectors) > 0 {
		fmt.Fprintf(w, "## Collector 状态\n\n")
		fmt.Fprintf(w, "| 场景 | 状态 | Poll 次数 | 错误 | Health |\n")
		fmt.Fprintf(w, "|---|---|---:|---|---|\n")
		for _, status := range collectors {
			errText := status.Error
			if errText == "" {
				errText = "-"
			}
			healthText := status.HealthError
			if healthText == "" && status.Health == nil {
				healthText = "missing snapshot"
			}
			if healthText == "" {
				healthText = "ok"
			}
			fmt.Fprintf(w, "| %s | %s | %d | %s | %s |\n", status.Name, status.State, status.PollCount, errText, healthText)
			if status.State == "failed" || status.HealthError != "" || status.Health == nil {
				failed = true
			}
		}
		fmt.Fprintln(w)
	}

	if len(a.reports) == 0 {
		if failed {
			fmt.Fprintln(w, "诊断不完整：至少一个 collector 失败，不能据此判定系统未发生异常。")
		} else {
			fmt.Fprintf(w, "未发现异常。系统在采集窗口内各项指标均低于告警阈值。\n")
		}
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
	if o.Scope == "system" {
		return "system"
	}
	parts := make([]string, 0, 5)
	if o.Comm != "" {
		parts = append(parts, o.Comm)
	}
	if o.Pid != 0 {
		parts = append(parts, fmt.Sprintf("pid=%d", o.Pid))
	}
	if o.Tid != 0 {
		parts = append(parts, fmt.Sprintf("tid=%d", o.Tid))
	}
	if o.LockAddress != 0 {
		parts = append(parts, fmt.Sprintf("lock=0x%x", o.LockAddress))
	}
	if o.Scope != "" {
		parts = append(parts, "scope="+o.Scope)
	}
	if len(parts) == 0 {
		return "system"
	}
	return strings.Join(parts, " ")
}

func aggregateKey(r schema.AnomalyReport) string {
	if isLockReport(r) {
		if address := lockAddress(r); address != 0 {
			return fmt.Sprintf("lock|%s|%d|address:%x",
				r.RootCauseCode, r.RelatedObject.Pid, address)
		}
		return fmt.Sprintf("lock|%s|%d|stack:%s",
			r.RootCauseCode, r.RelatedObject.Pid, stackSignature(r))
	}
	switch r.AnomalyType {
	case "系统调用热点":
		return fmt.Sprintf("%s|%s|%d|%s|%v",
			r.AnomalyType, r.RootCauseCode, r.RelatedObject.Pid, r.RelatedObject.Comm, r.KeyMetrics["syscall"])
	default:
		return fmt.Sprintf("%s|%s|%d|%d|%s|%s|%v",
			r.AnomalyType, r.RootCauseCode, r.RelatedObject.Pid, r.RelatedObject.Tid, r.RelatedObject.Comm,
			r.RelatedObject.Device, r.KeyMetrics["syscall"])
	}
}

func isLockReport(r schema.AnomalyReport) bool {
	return r.RootCauseCode == schema.RootCauseLockFutexContention ||
		r.RootCauseCode == schema.RootCauseLockKernelSyncWait
}

func lockAddress(r schema.AnomalyReport) uint64 {
	if r.RelatedObject.LockAddress != 0 {
		return r.RelatedObject.LockAddress
	}
	return metricUint64(r.KeyMetrics, "lock_address")
}

func windowsTouch(a, b schema.TimeWindow) bool {
	as, aStartErr := time.Parse(time.RFC3339Nano, a.Start)
	ae, aEndErr := time.Parse(time.RFC3339Nano, a.End)
	bs, bStartErr := time.Parse(time.RFC3339Nano, b.Start)
	be, bEndErr := time.Parse(time.RFC3339Nano, b.End)
	if aStartErr != nil || aEndErr != nil || bStartErr != nil || bEndErr != nil {
		return false
	}
	if !bs.After(ae) && !as.After(be) {
		return true
	}
	// Monotonic elapsed and wall-clock formatting are sampled separately by
	// some collectors, so nominally adjacent windows can have a sub-millisecond
	// wall gap. Keep that clock-sampling error within the same incident.
	const clockSamplingTolerance = 10 * time.Millisecond
	if bs.After(ae) {
		return bs.Sub(ae) <= clockSamplingTolerance
	}
	return as.Sub(be) <= clockSamplingTolerance
}

func stackSignature(r schema.AnomalyReport) string {
	var frames []string
	for _, ev := range r.EvidenceChain {
		if ev.Type != "stack" || ev.Func == "" {
			continue
		}
		frames = append(frames, ev.Func)
		if len(frames) >= 4 {
			break
		}
	}
	if len(frames) == 0 {
		return fmt.Sprintf("id:%v", r.KeyMetrics["stack_id"])
	}
	return strings.Join(frames, ";")
}

func addAffected(set map[uint32]struct{}, r schema.AnomalyReport) {
	if r.RelatedObject.Tid != 0 {
		set[r.RelatedObject.Tid] = struct{}{}
		return
	}
	if r.RelatedObject.Pid != 0 {
		set[r.RelatedObject.Pid] = struct{}{}
	}
}

func mergeReport(old, next schema.AnomalyReport) schema.AnomalyReport {
	if moreSevere(next, old) {
		old, next = next, old
	}
	old.TimeWindow = mergeWindow(old.TimeWindow, next.TimeWindow)
	if old.KeyMetrics == nil {
		old.KeyMetrics = make(map[string]interface{})
	}
	if old.EvidenceChain == nil {
		old.EvidenceChain = []schema.Evidence{}
	}
	if isLockReport(old) {
		maxMetric(old.KeyMetrics, "offcpu_ratio", metricFloat(old.KeyMetrics, "offcpu_ratio"), metricFloat(next.KeyMetrics, "offcpu_ratio"))
		sumMetric(old.KeyMetrics, "total_wait_ms", metricFloat(old.KeyMetrics, "total_wait_ms"), metricFloat(next.KeyMetrics, "total_wait_ms"))
		maxMetric(old.KeyMetrics, "p99_wait_ms", metricFloat(old.KeyMetrics, "p99_wait_ms"), metricFloat(next.KeyMetrics, "p99_wait_ms"))
		maxMetric(old.KeyMetrics, "max_wait_ms", metricFloat(old.KeyMetrics, "max_wait_ms"), metricFloat(next.KeyMetrics, "max_wait_ms"))
		maxMetric(old.KeyMetrics, "waiter_count", metricFloat(old.KeyMetrics, "waiter_count"), metricFloat(next.KeyMetrics, "waiter_count"))
		sumMetric(old.KeyMetrics, "block_count", metricFloat(old.KeyMetrics, "block_count"), metricFloat(next.KeyMetrics, "block_count"))
		syncEvidence(&old, "offcpu_ratio")
		syncEvidence(&old, "total_wait_ms")
		syncEvidence(&old, "p99_wait_ms")
		syncEvidence(&old, "max_wait_ms")
		syncEvidence(&old, "waiter_count")
		syncEvidence(&old, "block_count")
	} else if old.AnomalyType == "系统调用热点" {
		maxMetric(old.KeyMetrics, "calls_per_sec", metricFloat(old.KeyMetrics, "calls_per_sec"), metricFloat(next.KeyMetrics, "calls_per_sec"))
		maxMetric(old.KeyMetrics, "avg_lat_us", metricFloat(old.KeyMetrics, "avg_lat_us"), metricFloat(next.KeyMetrics, "avg_lat_us"))
		maxMetric(old.KeyMetrics, "max_lat_us", metricFloat(old.KeyMetrics, "max_lat_us"), metricFloat(next.KeyMetrics, "max_lat_us"))
		maxMetric(old.KeyMetrics, "total_ms_per_sec", metricFloat(old.KeyMetrics, "total_ms_per_sec"), metricFloat(next.KeyMetrics, "total_ms_per_sec"))
		syncEvidence(&old, "calls_per_sec")
		syncEvidence(&old, "avg_lat_us")
		syncEvidence(&old, "max_lat_us")
		syncEvidence(&old, "total_ms_per_sec")
	}
	return old
}

func moreSevere(a, b schema.AnomalyReport) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if isLockReport(a) {
		return severity(a, "offcpu_ratio", "max_wait_ms", "p99_wait_ms", "total_wait_ms", "block_count") >
			severity(b, "offcpu_ratio", "max_wait_ms", "p99_wait_ms", "total_wait_ms", "block_count")
	}
	switch a.AnomalyType {
	case "系统调用热点":
		return severity(a, "total_ms_per_sec", "calls_per_sec", "avg_lat_us") >
			severity(b, "total_ms_per_sec", "calls_per_sec", "avg_lat_us")
	default:
		return false
	}
}

func severity(r schema.AnomalyReport, names ...string) float64 {
	score := 0.0
	scale := 1.0
	for _, name := range names {
		score += metricFloat(r.KeyMetrics, name) * scale
		scale /= 1000000.0
	}
	return score
}

func mergeWindow(a, b schema.TimeWindow) schema.TimeWindow {
	as, aerr := time.Parse(time.RFC3339Nano, a.Start)
	bs, berr := time.Parse(time.RFC3339Nano, b.Start)
	if aerr == nil && berr == nil && bs.Before(as) {
		a.Start = b.Start
	}
	ae, aerr := time.Parse(time.RFC3339Nano, a.End)
	be, berr := time.Parse(time.RFC3339Nano, b.End)
	if aerr == nil && berr == nil && be.After(ae) {
		a.End = b.End
	}
	if start, err := time.Parse(time.RFC3339Nano, a.Start); err == nil {
		if end, err := time.Parse(time.RFC3339Nano, a.End); err == nil && end.After(start) {
			a.ElapsedMS = float64(end.Sub(start)) / float64(time.Millisecond)
		}
	}
	return a
}

func setAggregationMetrics(r *schema.AnomalyReport, count int, affected map[uint32]struct{}) {
	if r.KeyMetrics == nil {
		r.KeyMetrics = make(map[string]interface{})
	}
	if count > 1 {
		r.KeyMetrics["suppressed_report_count"] = count - 1
		r.KeyMetrics["merged_report_count"] = count
		addOrUpdateEvidence(r, "event", "suppressed_report_count", count-1, nil, "", "同类报告聚合后被压缩的条数")
	}
	if len(affected) > 1 && isLockReport(*r) {
		r.KeyMetrics["affected_tid_count"] = len(affected)
		addOrUpdateEvidence(r, "event", "affected_tid_count", len(affected), nil, "", "聚合窗口内涉及的线程数量")
	}
}

func maxMetric(m map[string]interface{}, name string, values ...float64) {
	max := 0.0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	m[name] = round2(max)
}

func sumMetric(m map[string]interface{}, name string, values ...float64) {
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	m[name] = round2(sum)
}

func metricFloat(m map[string]interface{}, name string) float64 {
	if m == nil {
		return 0
	}
	return valueFloat(m[name])
}

func metricUint64(m map[string]interface{}, name string) uint64 {
	if m == nil {
		return 0
	}
	switch x := m[name].(type) {
	case int:
		if x >= 0 {
			return uint64(x)
		}
	case int64:
		if x >= 0 {
			return uint64(x)
		}
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case float64:
		if x >= 0 {
			return uint64(x)
		}
	case float32:
		if x >= 0 {
			return uint64(x)
		}
	case json.Number:
		if n, err := x.Int64(); err == nil && n >= 0 {
			return uint64(n)
		}
	}
	return 0
}

func valueFloat(v interface{}) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	case uint32:
		return float64(x)
	case float64:
		return x
	case float32:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	default:
		return 0
	}
}

func syncEvidence(r *schema.AnomalyReport, name string) {
	v, ok := r.KeyMetrics[name]
	if !ok {
		return
	}
	for i := range r.EvidenceChain {
		if r.EvidenceChain[i].Name == name {
			r.EvidenceChain[i].Value = v
			return
		}
	}
	addOrUpdateEvidence(r, "metric", name, v, nil, "", "")
}

func addOrUpdateEvidence(r *schema.AnomalyReport, typ, name string, value, threshold interface{}, fn, desc string) {
	for i := range r.EvidenceChain {
		if r.EvidenceChain[i].Name != name {
			continue
		}
		if typ != "" {
			r.EvidenceChain[i].Type = typ
		}
		r.EvidenceChain[i].Value = value
		if threshold != nil {
			r.EvidenceChain[i].Threshold = threshold
		}
		if fn != "" {
			r.EvidenceChain[i].Func = fn
		}
		if desc != "" {
			r.EvidenceChain[i].Desc = desc
		}
		return
	}
	r.EvidenceChain = append(r.EvidenceChain, schema.Evidence{
		Type:      typ,
		Name:      name,
		Value:     value,
		Threshold: threshold,
		Func:      fn,
		Desc:      desc,
	})
	sort.SliceStable(r.EvidenceChain, func(i, j int) bool {
		if r.EvidenceChain[i].Type != r.EvidenceChain[j].Type {
			return r.EvidenceChain[i].Type < r.EvidenceChain[j].Type
		}
		return r.EvidenceChain[i].Name < r.EvidenceChain[j].Name
	})
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
