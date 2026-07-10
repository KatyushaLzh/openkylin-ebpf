package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

var anomalyReportRequiredFields = []string{
	"anomaly_type", "root_cause_code", "related_object", "key_metrics",
	"time_window", "suspected_root_cause", "confidence", "evidence_chain", "suggestion",
}

var diagnosticSessionRequiredFields = []string{
	"schema_version", "started_at", "ended_at", "elapsed_ms", "environment",
	"configuration", "collectors", "partial", "reports",
}

// DecodeAnomalyReportJSON rejects unknown fields, missing required fields,
// trailing values and semantic violations. It is the canonical artifact read
// path shared by the checker and compactor.
func DecodeAnomalyReportJSON(data []byte) (AnomalyReport, error) {
	var report AnomalyReport
	if err := requireReportFields(data, "AnomalyReport"); err != nil {
		return report, err
	}
	if err := decodeStrictJSON(data, &report); err != nil {
		return report, err
	}
	if err := ValidateAnomalyReport(report); err != nil {
		return report, err
	}
	return report, nil
}

// DecodeDiagnosticSessionJSON applies strict presence and semantic checks to
// the session envelope and every nested report.
func DecodeDiagnosticSessionJSON(data []byte) (DiagnosticSession, error) {
	var session DiagnosticSession
	root, err := requireObjectFields(data, "DiagnosticSession", diagnosticSessionRequiredFields...)
	if err != nil {
		return session, err
	}
	if _, err := requireObjectFields(root["environment"], "environment",
		"hostname", "os", "architecture", "kernel_release", "btf"); err != nil {
		return session, err
	}
	configuration, err := requireObjectFields(root["configuration"], "configuration",
		"scenario", "interval_ms", "sustain", "allow_partial", "thresholds")
	if err != nil {
		return session, err
	}
	if raw, ok := configuration["target_pid"]; ok {
		if err := requirePositiveUint32(raw, "configuration.target_pid"); err != nil {
			return session, err
		}
	}
	var collectors []json.RawMessage
	if err := json.Unmarshal(root["collectors"], &collectors); err != nil {
		return session, fmt.Errorf("collectors must be an array: %w", err)
	}
	for i, raw := range collectors {
		collector, err := requireObjectFields(raw, fmt.Sprintf("collectors[%d]", i),
			"name", "requested", "initialized", "state", "poll_count")
		if err != nil {
			return session, err
		}
		if health, ok := collector["health"]; ok {
			if _, err := requireObjectFields(health, fmt.Sprintf("collectors[%d].health", i),
				"program_runtime_ns", "program_run_count", "map_memory_bytes", "counters"); err != nil {
				return session, err
			}
		}
		for _, field := range []string{"last_poll_at", "error", "health_error"} {
			if value, ok := collector[field]; ok {
				if err := requireNonEmptyString(value, fmt.Sprintf("collectors[%d].%s", i, field)); err != nil {
					return session, err
				}
			}
		}
	}
	var reports []json.RawMessage
	if err := json.Unmarshal(root["reports"], &reports); err != nil {
		return session, fmt.Errorf("reports must be an array: %w", err)
	}
	for i, raw := range reports {
		if err := requireReportFields(raw, fmt.Sprintf("reports[%d]", i)); err != nil {
			return session, err
		}
	}
	if err := decodeStrictJSON(data, &session); err != nil {
		return session, err
	}
	if err := ValidateDiagnosticSession(session); err != nil {
		return session, err
	}
	return session, nil
}

func requireReportFields(data []byte, where string) error {
	root, err := requireObjectFields(data, where, anomalyReportRequiredFields...)
	if err != nil {
		return err
	}
	if _, err := requireObjectFields(root["time_window"], where+".time_window",
		"start", "end", "elapsed_ms"); err != nil {
		return err
	}
	related, err := requireObjectFields(root["related_object"], where+".related_object")
	if err != nil {
		return err
	}
	for _, field := range []string{"pid", "tid"} {
		if value, ok := related[field]; ok {
			if err := requirePositiveUint32(value, where+".related_object."+field); err != nil {
				return err
			}
		}
	}
	if value, ok := related["lock_address"]; ok {
		if err := requirePositiveUint64(value, where+".related_object.lock_address"); err != nil {
			return err
		}
	}
	for _, field := range []string{"comm", "device", "scope"} {
		if value, ok := related[field]; ok {
			if err := requireNonEmptyString(value, where+".related_object."+field); err != nil {
				return err
			}
		}
	}
	var evidence []json.RawMessage
	if err := json.Unmarshal(root["evidence_chain"], &evidence); err != nil {
		return fmt.Errorf("%s.evidence_chain must be an array: %w", where, err)
	}
	for i, raw := range evidence {
		if _, err := requireObjectFields(raw, fmt.Sprintf("%s.evidence_chain[%d]", where, i),
			"type", "name"); err != nil {
			return err
		}
	}
	return nil
}

func requirePositiveUint32(data []byte, where string) error {
	var value uint32
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%s must be a positive uint32: %w", where, err)
	}
	if value == 0 {
		return fmt.Errorf("%s must be positive", where)
	}
	return nil
}

func requirePositiveUint64(data []byte, where string) error {
	var value uint64
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%s must be a positive uint64: %w", where, err)
	}
	if value == 0 {
		return fmt.Errorf("%s must be positive", where)
	}
	return nil
}

func requireNonEmptyString(data []byte, where string) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%s must be a non-empty string: %w", where, err)
	}
	if value == "" {
		return fmt.Errorf("%s must be a non-empty string", where)
	}
	return nil
}

func requireObjectFields(data []byte, where string, fields ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, fmt.Errorf("%s must be an object: %w", where, err)
	}
	if object == nil {
		return nil, fmt.Errorf("%s must be an object", where)
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return nil, fmt.Errorf("%s missing required field %q", where, field)
		}
	}
	return object, nil
}

func decodeStrictJSON(data []byte, dst interface{}) error {
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rejectDuplicateObjectKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var scanValue func() error
	scanValue = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON object key %q", key)
				}
				seen[key] = struct{}{}
				if err := scanValue(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return fmt.Errorf("invalid JSON object terminator: %v", err)
			}
		case '[':
			for dec.More() {
				if err := scanValue(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return fmt.Errorf("invalid JSON array terminator: %v", err)
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	return scanValue()
}
