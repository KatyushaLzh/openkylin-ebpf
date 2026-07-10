package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

var validRootCauseCodes = map[string]struct{}{
	RootCauseCPUComputeHotspot: {}, RootCauseCPUSchedulerPressure: {},
	RootCauseIOQueueCongestion: {}, RootCauseIODeviceLatency: {},
	RootCauseMemReclaimPressure: {}, RootCauseMemOOMVictim: {},
	RootCauseLockFutexContention: {}, RootCauseLockKernelSyncWait: {},
	RootCauseSyscallHighFrequency: {}, RootCauseSyscallHighLatency: {},
}

var validScopes = map[string]struct{}{"": {}, "process": {}, "target_tree": {}, "system": {}}

var requiredThresholds = []string{
	"cpu_util", "io_p99_ms", "mem_available_floor_pct", "lock_offcpu_ratio", "syscall_calls_per_sec",
}

// ValidRootCauseCode reports whether code is part of the stable machine API.
func ValidRootCauseCode(code string) bool {
	_, ok := validRootCauseCodes[code]
	return ok
}

// ValidateAnomalyReport enforces the same invariants as the published JSON
// schema before a JSON/JSONL artifact is emitted.
func ValidateAnomalyReport(r AnomalyReport) error {
	if r.AnomalyType == "" {
		return fmt.Errorf("anomaly_type is required")
	}
	if !ValidRootCauseCode(r.RootCauseCode) {
		return fmt.Errorf("invalid root_cause_code %q", r.RootCauseCode)
	}
	obj := r.RelatedObject
	if obj.Pid == 0 && obj.Tid == 0 && obj.Comm == "" && obj.Device == "" && obj.LockAddress == 0 && obj.Scope == "" {
		return fmt.Errorf("related_object has no identifiable target")
	}
	if _, ok := validScopes[obj.Scope]; !ok {
		return fmt.Errorf("invalid related_object.scope %q", obj.Scope)
	}
	if obj.Scope == "system" && (obj.Pid != 0 || obj.Tid != 0 || obj.LockAddress != 0) {
		return fmt.Errorf("system-scoped related_object must not claim a process, thread, or lock instance")
	}
	switch r.RootCauseCode {
	case RootCauseCPUComputeHotspot, RootCauseCPUSchedulerPressure:
		if obj.Pid == 0 || obj.Tid == 0 {
			return fmt.Errorf("CPU report requires TGID pid and hottest tid")
		}
	case RootCauseIOQueueCongestion, RootCauseIODeviceLatency:
		if obj.Device == "" {
			return fmt.Errorf("I/O report requires related_object.device")
		}
	case RootCauseLockFutexContention:
		if obj.Pid == 0 || obj.Tid == 0 || obj.LockAddress == 0 {
			return fmt.Errorf("futex report requires TGID pid, waiter tid, and lock_address")
		}
	case RootCauseLockKernelSyncWait:
		if obj.Pid == 0 || obj.Tid == 0 {
			return fmt.Errorf("kernel synchronization report requires TGID pid and waiter tid")
		}
	case RootCauseSyscallHighFrequency, RootCauseSyscallHighLatency:
		if obj.Pid == 0 {
			return fmt.Errorf("syscall report requires TGID pid")
		}
	}
	if len(r.KeyMetrics) == 0 {
		return fmt.Errorf("key_metrics is empty")
	}
	if _, err := json.Marshal(r.KeyMetrics); err != nil {
		return fmt.Errorf("key_metrics is not valid JSON: %w", err)
	}
	start, err := time.Parse(time.RFC3339Nano, r.TimeWindow.Start)
	if err != nil {
		return fmt.Errorf("time_window.start: %w", err)
	}
	end, err := time.Parse(time.RFC3339Nano, r.TimeWindow.End)
	if err != nil {
		return fmt.Errorf("time_window.end: %w", err)
	}
	if !end.After(start) {
		return fmt.Errorf("time_window.start must be before end")
	}
	wantElapsed := float64(end.Sub(start)) / float64(time.Millisecond)
	if !finite(r.TimeWindow.ElapsedMS) || r.TimeWindow.ElapsedMS <= 0 || math.Abs(r.TimeWindow.ElapsedMS-wantElapsed) > math.Max(0.01, wantElapsed*0.001) {
		return fmt.Errorf("time_window.elapsed_ms %.6f does not match start/end %.6f", r.TimeWindow.ElapsedMS, wantElapsed)
	}
	if r.SuspectedRootCause == "" {
		return fmt.Errorf("suspected_root_cause is required")
	}
	if !finite(r.Confidence) || r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("confidence must be in [0,1]")
	}
	if len(r.EvidenceChain) == 0 {
		return fmt.Errorf("evidence_chain is empty")
	}
	for i, evidence := range r.EvidenceChain {
		if evidence.Type == "" || evidence.Name == "" {
			return fmt.Errorf("evidence_chain[%d] requires type and name", i)
		}
	}
	if _, err := json.Marshal(r.EvidenceChain); err != nil {
		return fmt.Errorf("evidence_chain is not valid JSON: %w", err)
	}
	if r.Suggestion == "" {
		return fmt.Errorf("suggestion is required")
	}
	return nil
}

// ValidateDiagnosticSession validates the JSON envelope and every nested report.
func ValidateDiagnosticSession(s DiagnosticSession) error {
	if s.SchemaVersion != "1.0" {
		return fmt.Errorf("unsupported schema_version %q", s.SchemaVersion)
	}
	start, err := time.Parse(time.RFC3339Nano, s.StartedAt)
	if err != nil {
		return fmt.Errorf("started_at: %w", err)
	}
	end, err := time.Parse(time.RFC3339Nano, s.EndedAt)
	if err != nil {
		return fmt.Errorf("ended_at: %w", err)
	}
	wantElapsed := float64(end.Sub(start)) / float64(time.Millisecond)
	if end.Before(start) || !finite(s.ElapsedMS) || s.ElapsedMS < 0 || math.Abs(s.ElapsedMS-wantElapsed) > math.Max(0.01, wantElapsed*0.001) {
		return fmt.Errorf("invalid session time range")
	}
	if s.Environment.Hostname == "" || s.Environment.OS == "" || s.Environment.Architecture == "" || s.Environment.KernelRelease == "" {
		return fmt.Errorf("incomplete runtime environment")
	}
	expected := map[string]struct{}{}
	switch s.Configuration.Scenario {
	case "cpu", "io", "mem", "lock", "syscall":
		expected[s.Configuration.Scenario] = struct{}{}
	case "all":
		for _, name := range []string{"cpu", "io", "mem", "lock", "syscall"} {
			expected[name] = struct{}{}
		}
	default:
		return fmt.Errorf("invalid scenario %q", s.Configuration.Scenario)
	}
	if s.Configuration.IntervalMS <= 0 || s.Configuration.Sustain < 1 {
		return fmt.Errorf("invalid session configuration")
	}
	for _, name := range requiredThresholds {
		value, ok := s.Configuration.Thresholds[name]
		if !ok || !finite(value) || value < 0 {
			return fmt.Errorf("invalid or missing threshold %q", name)
		}
	}
	if len(s.Configuration.Thresholds) != len(requiredThresholds) {
		return fmt.Errorf("thresholds must contain exactly the published five fields")
	}
	if len(s.Collectors) == 0 {
		return fmt.Errorf("collectors is empty")
	}
	failed := false
	seen := make(map[string]struct{}, len(s.Collectors))
	for i, status := range s.Collectors {
		if _, ok := expected[status.Name]; !ok {
			return fmt.Errorf("collectors[%d] is not requested by scenario: %q", i, status.Name)
		}
		if _, duplicate := seen[status.Name]; duplicate {
			return fmt.Errorf("duplicate collector %q", status.Name)
		}
		seen[status.Name] = struct{}{}
		if !status.Requested {
			return fmt.Errorf("collectors[%d] has incomplete lifecycle state", i)
		}
		switch status.State {
		case "stopped":
			if !status.Initialized {
				return fmt.Errorf("collectors[%d] stopped without initialization", i)
			}
			if status.Error != "" || status.HealthError != "" || status.Health == nil {
				return fmt.Errorf("collectors[%d] stopped without a clean health snapshot", i)
			}
		case "failed":
			// Initialization and Poll failures are both valid terminal states.
		default:
			return fmt.Errorf("collectors[%d] has non-terminal state %q", i, status.State)
		}
		if status.LastPollAt != "" {
			if _, err := time.Parse(time.RFC3339Nano, status.LastPollAt); err != nil {
				return fmt.Errorf("collectors[%d].last_poll_at: %w", i, err)
			}
		}
		if status.State == "failed" {
			failed = true
			if status.Error == "" {
				return fmt.Errorf("collectors[%d] failed without error", i)
			}
		}
		if status.Health != nil && status.Health.Counters == nil {
			return fmt.Errorf("collectors[%d].health.counters must be an object", i)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("collector coverage mismatch: got %d want %d", len(seen), len(expected))
	}
	if failed != s.Partial {
		return fmt.Errorf("partial=%t does not match collector failure=%t", s.Partial, failed)
	}
	if s.Reports == nil {
		return fmt.Errorf("reports must be an array, not null")
	}
	for i, report := range s.Reports {
		if err := ValidateAnomalyReport(report); err != nil {
			return fmt.Errorf("reports[%d]: %w", i, err)
		}
		if s.Configuration.Scenario != "all" && !strings.HasPrefix(report.RootCauseCode, s.Configuration.Scenario+".") {
			return fmt.Errorf("reports[%d] root_cause_code %q does not match scenario %q", i, report.RootCauseCode, s.Configuration.Scenario)
		}
	}
	return nil
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
