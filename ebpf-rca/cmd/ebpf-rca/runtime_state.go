package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/schema"
)

const diagnosticSchemaVersion = "1.0"

var allCollectorNames = []string{"cpu", "io", "mem", "lock", "syscall"}

type collectorTracker struct {
	order    []string
	statuses map[string]*schema.CollectorStatus
	partial  bool
}

func newCollectorTracker(scenario string) *collectorTracker {
	names := []string{scenario}
	if scenario == "all" {
		names = append([]string(nil), allCollectorNames...)
	}
	t := &collectorTracker{order: names, statuses: make(map[string]*schema.CollectorStatus, len(names))}
	for _, name := range names {
		t.statuses[name] = &schema.CollectorStatus{Name: name, Requested: true, State: "not_started"}
	}
	return t
}

func (t *collectorTracker) initialized(name string) {
	s := t.statuses[name]
	if s == nil {
		return
	}
	s.Initialized = true
	s.State = "ready"
}

func (t *collectorTracker) pollOK(name string, at time.Time) {
	s := t.statuses[name]
	if s == nil {
		return
	}
	s.State = "running"
	s.PollCount++
	s.LastPollAt = at.UTC().Format(time.RFC3339Nano)
}

func (t *collectorTracker) failed(name string, err error) {
	s := t.statuses[name]
	if s == nil {
		return
	}
	s.State = "failed"
	if err != nil {
		s.Error = err.Error()
	}
	t.partial = true
}

func (t *collectorTracker) healthUnavailable(err error) {
	if err == nil {
		return
	}
	for _, status := range t.statuses {
		status.HealthError = err.Error()
	}
}

func (t *collectorTracker) captureHealth(name string, value interface{}) {
	provider, ok := value.(collector.HealthProvider)
	if !ok {
		return
	}
	h, err := provider.HealthSnapshot()
	s := t.statuses[name]
	if s == nil {
		return
	}
	if err != nil {
		s.HealthError = err.Error()
		return
	}
	s.Health = &schema.CollectorHealth{
		ProgramRuntimeNS: h.ProgramRuntimeNS,
		ProgramRunCount:  h.ProgramRunCount,
		MapMemoryBytes:   h.MapMemoryBytes,
		Counters:         h.Counters,
	}
	if err := healthIntegrityError(h.Counters); err != nil {
		s.HealthError = err.Error()
	}
}

// failUnhealthy turns an unreadable or data-loss health snapshot into a
// terminal collector failure. A zero-report run is only a clean observation
// when every requested collector can prove that its data path stayed intact.
func (t *collectorTracker) failUnhealthy() error {
	var failures []string
	for _, name := range t.order {
		s := t.statuses[name]
		if s == nil || s.HealthError == "" {
			continue
		}
		failures = append(failures, fmt.Sprintf("%s: %s", name, s.HealthError))
		if s.State != "failed" {
			s.State = "failed"
			s.Error = "collector health: " + s.HealthError
		}
		t.partial = true
	}
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("collector health validation failed: %s", strings.Join(failures, "; "))
}

func healthIntegrityError(counters map[string]uint64) error {
	var failed []string
	for name, value := range counters {
		if value == 0 {
			continue
		}
		if strings.HasSuffix(name, "update_fail") || strings.HasSuffix(name, "_miss") {
			failed = append(failed, fmt.Sprintf("%s=%d", name, value))
		}
	}
	if len(failed) == 0 {
		return nil
	}
	sort.Strings(failed)
	return fmt.Errorf("data-integrity counters are non-zero: %s", strings.Join(failed, ", "))
}

func (t *collectorTracker) finish() {
	for _, s := range t.statuses {
		if s.State == "ready" || s.State == "running" {
			s.State = "stopped"
		} else if s.State == "pending" {
			s.State = "not_started"
		}
	}
}

func (t *collectorTracker) snapshot() []schema.CollectorStatus {
	out := make([]schema.CollectorStatus, 0, len(t.order))
	for _, name := range t.order {
		if s := t.statuses[name]; s != nil {
			out = append(out, *s)
		}
	}
	return out
}

func finalizeReport(r schema.AnomalyReport) schema.AnomalyReport {
	start, startErr := time.Parse(time.RFC3339Nano, r.TimeWindow.Start)
	end, endErr := time.Parse(time.RFC3339Nano, r.TimeWindow.End)
	if startErr == nil && endErr == nil && end.After(start) {
		r.TimeWindow.ElapsedMS = float64(end.Sub(start)) / float64(time.Millisecond)
	}
	return r
}

func makeDiagnosticSession(cfg config, started, ended time.Time, reports []schema.AnomalyReport) schema.DiagnosticSession {
	if reports == nil {
		reports = []schema.AnomalyReport{}
	}
	return schema.DiagnosticSession{
		SchemaVersion: diagnosticSchemaVersion,
		StartedAt:     started.UTC().Format(time.RFC3339Nano),
		EndedAt:       ended.UTC().Format(time.RFC3339Nano),
		ElapsedMS:     float64(ended.Sub(started)) / float64(time.Millisecond),
		Environment:   runtimeEnvironment(),
		Configuration: schema.SessionConfiguration{
			Scenario:     cfg.scenario,
			IntervalMS:   cfg.interval.Milliseconds(),
			Sustain:      cfg.sustain,
			TargetPID:    cfg.targetPID,
			AllowPartial: cfg.allowPartial,
			Thresholds: map[string]float64{
				"cpu_util":                cfg.threshold.CPU,
				"io_p99_ms":               cfg.threshold.IOP99Ms,
				"mem_available_floor_pct": cfg.threshold.MemAvailFloorPct,
				"lock_offcpu_ratio":       cfg.threshold.LockOffcpuRatio,
				"syscall_calls_per_sec":   cfg.threshold.SyscallCallsPerSec,
			},
		},
		Collectors: cfg.tracker.snapshot(),
		Partial:    cfg.tracker.partial,
		Reports:    reports,
	}
}

func runtimeEnvironment() schema.RuntimeEnvironment {
	host, _ := os.Hostname()
	release := "unknown"
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		release = utsField(uts.Release[:])
	}
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	return schema.RuntimeEnvironment{
		Hostname:      host,
		OS:            runtime.GOOS,
		Architecture:  runtime.GOARCH,
		KernelRelease: release,
		BTF:           btfErr == nil,
	}
}

// Linux exposes Utsname fields as int8 on some architectures and uint8 on
// others. Keep the conversion architecture-neutral so cross-builds exercise
// the same session metadata path as the native build.
func utsField[T ~int8 | ~uint8](chars []T) string {
	b := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
