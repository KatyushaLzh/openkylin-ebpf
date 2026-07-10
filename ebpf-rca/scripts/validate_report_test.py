#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate_report.py")
SPEC = importlib.util.spec_from_file_location("validate_report", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
validate_report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_report)


def thresholds():
    return {
        "cpu_util": 0.9,
        "io_p99_ms": 20,
        "mem_available_floor_pct": 15,
        "lock_offcpu_ratio": 0.3,
        "syscall_calls_per_sec": 10000,
    }


def report(code="cpu.compute_hotspot", related=None):
    return {
        "anomaly_type": "CPU异常占用",
        "root_cause_code": code,
        "related_object": related or {"pid": 123, "tid": 123, "comm": "load", "scope": "process"},
        "key_metrics": {"process_cpu_cores": 1.0},
        "time_window": {
            "start": "2026-07-10T00:00:00Z",
            "end": "2026-07-10T00:00:01Z",
            "elapsed_ms": 1000,
        },
        "suspected_root_cause": "CPU 计算热点",
        "confidence": 0.9,
        "evidence_chain": [{"type": "metric", "name": "process_cpu_cores", "value": 1.0}],
        "suggestion": "profile the workload",
    }


def collector(name, state="stopped"):
    value = {
        "name": name,
        "requested": True,
        "initialized": state == "stopped",
        "state": state,
        "poll_count": 1 if state == "stopped" else 0,
    }
    if state == "failed":
        value["error"] = "load failed"
    else:
        value["health"] = {
            "program_runtime_ns": 1,
            "program_run_count": 1,
            "map_memory_bytes": 4096,
            "counters": {"map_update_fail": 0},
        }
    return value


def session(scenario="cpu", reports=None):
    names = sorted(validate_report.SCENARIOS) if scenario == "all" else [scenario]
    return {
        "schema_version": "1.0",
        "started_at": "2026-07-10T00:00:00Z",
        "ended_at": "2026-07-10T00:00:01Z",
        "elapsed_ms": 1000,
        "environment": {
            "hostname": "test",
            "os": "linux",
            "architecture": "amd64",
            "kernel_release": "6.6.0",
            "btf": True,
        },
        "configuration": {
            "scenario": scenario,
            "interval_ms": 1000,
            "sustain": 2,
            "allow_partial": False,
            "thresholds": thresholds(),
        },
        "collectors": [collector(name) for name in names],
        "partial": False,
        "reports": [] if reports is None else reports,
    }


class StrictJSONTests(unittest.TestCase):
    def test_rejects_noisy_trailing_text_nan_and_duplicate_keys(self):
        for text in ('{"a": 1} trailing', '{"a": NaN}', '{"a": 1, "a": 2}'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    validate_report.decode_json_values(text)

    def test_rejects_malformed_jsonl_without_skipping_line(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            validate_report.decode_json_values('{"a": 1}\nnot-json\n{"b": 2}\n')

    def test_array_member_cannot_be_silently_skipped(self):
        values = validate_report.decode_json_values(json.dumps([report(), 7]))
        with self.assertRaisesRegex(ValueError, "must be an object"):
            validate_report.iter_validated_documents(values)


class SessionValidationTests(unittest.TestCase):
    def test_strict_session_decoder_rejects_all_schema_error_classes(self):
        valid = session()
        duplicate = json.dumps(valid).replace(
            '"schema_version": "1.0"',
            '"schema_version": "1.0", "schema_version": "1.0"',
            1,
        )

        unknown = session()
        unknown["unexpected"] = True
        nonfinite = session()
        nonfinite["configuration"]["thresholds"]["cpu_util"] = float("nan")
        missing = session()
        del missing["environment"]
        semantic = session()
        semantic["elapsed_ms"] = 1

        invalid_documents = [
            duplicate,
            json.dumps(unknown),
            json.dumps(nonfinite),
            json.dumps(missing),
            json.dumps(semantic),
        ]
        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    validate_report.decode_diagnostic_session_json(document)

    def test_empty_report_session_is_valid(self):
        documents = validate_report.iter_validated_documents([session("all")])
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0][0], "session")
        self.assertEqual(documents[0][1]["reports"], [])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "idle.json"
            path.write_text(json.dumps(session("all")), encoding="utf-8")
            rows = validate_report.validate_paths([path])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(rows[0]["scenario"], "all")

    def test_requires_exact_collector_coverage(self):
        value = session("all")
        value["collectors"].pop()
        with self.assertRaisesRegex(ValueError, "coverage mismatch"):
            validate_report.validate_diagnostic_session(value)

    def test_rejects_nonterminal_collector_state(self):
        value = session()
        value["collectors"][0]["state"] = "running"
        with self.assertRaisesRegex(ValueError, "non-terminal"):
            validate_report.validate_diagnostic_session(value)

    def test_rejects_not_started_as_incomplete_terminal_state(self):
        value = session()
        value["collectors"][0] = collector("cpu", "not_started")
        with self.assertRaisesRegex(ValueError, "non-terminal"):
            validate_report.validate_diagnostic_session(value)

    def test_requires_all_product_thresholds(self):
        value = session()
        del value["configuration"]["thresholds"]["io_p99_ms"]
        with self.assertRaisesRegex(ValueError, "thresholds missing"):
            validate_report.validate_diagnostic_session(value)

    def test_partial_must_match_failed_collector(self):
        value = session()
        value["collectors"][0] = collector("cpu", "failed")
        with self.assertRaisesRegex(ValueError, "partial does not match"):
            validate_report.validate_diagnostic_session(value)

    def test_failed_session_is_parseable_but_never_pass_evidence(self):
        for reports in ([], [report()]):
            with self.subTest(report_count=len(reports)):
                value = session("cpu", reports)
                value["collectors"][0] = collector("cpu", "failed")
                value["partial"] = True
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "failed.json"
                    path.write_text(json.dumps(value), encoding="utf-8")
                    rows = validate_report.validate_paths([path])
                lifecycle = [row for row in rows if row["report_index"] == 0]
                self.assertEqual(len(lifecycle), 1)
                self.assertEqual(lifecycle[0]["status"], "FAIL")
                self.assertEqual(lifecycle[0]["score"], 0)
                self.assertIn("collector_failure", lifecycle[0]["errors"])

    def test_single_scenario_rejects_cross_scenario_report(self):
        value = session("cpu", [report("syscall.high_frequency", {"pid": 123, "scope": "process"})])
        with self.assertRaisesRegex(ValueError, "does not match scenario"):
            validate_report.validate_diagnostic_session(value)

    def test_rejects_fixed_width_session_integer_overflow(self):
        value = session()
        value["configuration"]["target_pid"] = 2**32
        with self.assertRaisesRegex(ValueError, "4294967295"):
            validate_report.validate_diagnostic_session(value)

        value = session()
        value["collectors"][0]["poll_count"] = 2**64
        with self.assertRaisesRegex(ValueError, "18446744073709551615"):
            validate_report.validate_diagnostic_session(value)


class ReportValidationTests(unittest.TestCase):
    def test_optional_evidence_text_fields_must_be_strings(self):
        for field in ("desc", "func"):
            with self.subTest(field=field):
                value = report()
                value["evidence_chain"][0][field] = 123
                with self.assertRaisesRegex(ValueError, rf"{field} must be a string"):
                    validate_report.validate_anomaly_report(value)

    def test_futex_report_requires_lock_address(self):
        value = report(
            "lock.futex_contention",
            {"pid": 123, "tid": 124, "comm": "load", "scope": "process"},
        )
        with self.assertRaisesRegex(ValueError, "lock_address is required"):
            validate_report.validate_anomaly_report(value)

    def test_elapsed_must_match_observation_window(self):
        value = report()
        value["time_window"]["elapsed_ms"] = 500
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_report.validate_anomaly_report(value)

    def test_rejects_related_identifier_overflow(self):
        value = report()
        value["related_object"]["pid"] = 2**32
        with self.assertRaisesRegex(ValueError, "4294967295"):
            validate_report.validate_anomaly_report(value)

        value = report()
        value["related_object"]["lock_address"] = 2**64
        with self.assertRaisesRegex(ValueError, "18446744073709551615"):
            validate_report.validate_anomaly_report(value)


if __name__ == "__main__":
    unittest.main()
