#!/usr/bin/env python3
"""Focused unit tests for the strict accuracy metric aggregation."""

from __future__ import annotations

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("eval_accuracy.py")
SPEC = importlib.util.spec_from_file_location("eval_accuracy", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
accuracy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(accuracy)


def positive_check(*, tp: int, fp: int, type_match: bool, code_match: bool, object_match: bool) -> dict[str, object]:
    return {
        "kind": "positive",
        "passed": tp == 1 and fp == 0,
        "evaluation_valid": True,
        "report_count": tp + fp,
        "matched_reports": [{}] if tp else [],
        "extra_report_count": fp,
        "type_match": type_match,
        "root_cause_code_match": code_match,
        "workload_object_match": object_match,
        "true_positive": tp,
        "true_negative": 0,
        "false_positive": fp,
        "false_negative": 1 - tp,
    }


def negative_check(report_count: int) -> dict[str, object]:
    return {
        "kind": "negative",
        "passed": report_count == 0,
        "evaluation_valid": True,
        "report_count": report_count,
        "matched_reports": [],
        "extra_report_count": 0,
        "true_positive": 0,
        "true_negative": 1 if report_count == 0 else 0,
        "false_positive": report_count,
        "false_negative": 0,
    }


class AccuracyMetricTest(unittest.TestCase):
    def row(self, scenario: str, check: dict[str, object], repeat: int = 1) -> dict[str, object]:
        runner_rc = 0 if check["passed"] else 1
        status = {
            "schema_version": "1.0",
            "scenario": scenario,
            "complete": True,
            "workload_rc": 0,
            "tool_rc": 0,
            "truth_rc": 0,
            "health_rc": 0,
            "checker_rc": runner_rc,
        }
        row: dict[str, object] = {
            "scenario": scenario,
            "repeat": repeat,
            "command_rc": runner_rc,
            "artifact_dir": "runs/test",
            "check_path": "runs/test/check.json",
            "started_at": "",
            "ended_at": "",
            "elapsed_sec": "1.0",
        }
        row.update(accuracy.classify_run(
            scenario, check, int(row["command_rc"]), run_status=status, require_status=True,
        ))
        return row

    def test_tool_failure_cannot_contribute_true_positive(self) -> None:
        check = positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True)
        status = {
            "schema_version": "1.0", "scenario": "cpu", "complete": True,
            "workload_rc": 0, "tool_rc": 1, "truth_rc": 0, "health_rc": 0, "checker_rc": 0,
        }
        row = accuracy.classify_run(
            "cpu", check, 1, run_status=status, require_status=True,
        )
        self.assertEqual("infra_error", row["outcome"])
        self.assertEqual(1, row["infra_error"])
        self.assertEqual(0, row["TP"])

    def test_missing_component_status_is_infrastructure_error(self) -> None:
        check = positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True)
        row = accuracy.classify_run("cpu", check, 0, require_status=True)
        self.assertEqual(1, row["infra_error"])

    def test_from_existing_keeps_status_only_failed_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "cpu_r1" / "cpu"
            artifact.mkdir(parents=True)
            status = {
                "schema_version": "1.0", "scenario": "cpu", "complete": True,
                "workload_rc": 0, "tool_rc": 1, "truth_rc": 0, "health_rc": 0, "checker_rc": 125,
            }
            (artifact / "run_status.json").write_text(json.dumps(status), encoding="utf-8")
            rows = accuracy.collect_existing(Path(tmp))
        self.assertEqual(1, len(rows))
        self.assertEqual(1, rows[0]["infra_error"])
        self.assertEqual("infra_error", rows[0]["outcome"])

    def test_tp_and_extra_fp_coexist(self) -> None:
        row = self.row(
            "cpu",
            positive_check(tp=1, fp=2, type_match=True, code_match=True, object_match=True),
        )
        self.assertEqual("TP+FP", row["outcome"])
        self.assertEqual(1, row["TP"])
        self.assertEqual(2, row["FP"])
        self.assertEqual(0, row["FN"])
        self.assertFalse(row["e2e_pass"])

    def test_five_class_macro_and_negative_run_fpr(self) -> None:
        rows = [
            self.row("cpu", positive_check(tp=1, fp=1, type_match=True, code_match=True, object_match=True)),
            self.row("io", positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True)),
            self.row("mem", positive_check(tp=0, fp=1, type_match=True, code_match=False, object_match=True)),
            self.row("lock", positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True)),
            self.row("syscall", positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True)),
            self.row("idle", negative_check(0)),
            self.row("normal_mem", negative_check(2)),
        ]
        summaries, totals = accuracy.summarize(rows)

        self.assertTrue(totals["five_positive_classes_complete"])
        self.assertAlmostEqual(70.0, totals["macro_precision"])
        self.assertAlmostEqual(80.0, totals["macro_recall"])
        self.assertAlmostEqual(73.3333333333, totals["macro_f1"])
        self.assertAlmostEqual(80.0, totals["root_cause_code_accuracy"])
        self.assertAlmostEqual(100.0, totals["object_top1_accuracy"])
        self.assertAlmostEqual(50.0, totals["negative_false_positive_rate"])
        self.assertEqual(4, totals["TP"])
        self.assertEqual(4, totals["FP"])
        self.assertEqual(1, totals["FN"])
        self.assertEqual(1, totals["TN"])

        by_scenario = {item["scenario"]: item for item in summaries}
        self.assertAlmostEqual(50.0, by_scenario["cpu"]["precision"])
        self.assertAlmostEqual(100.0, by_scenario["cpu"]["recall"])
        self.assertAlmostEqual(66.6666666667, by_scenario["cpu"]["f1"])
        self.assertEqual(2, by_scenario["normal_mem"]["FP"])
        self.assertAlmostEqual(100.0, by_scenario["normal_mem"]["false_positive_rate"])

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            accuracy.write_outputs(out, rows, summaries, totals, "stress", 10)
            with (out / "accuracy_runs.csv").open(encoding="utf-8", newline="") as f:
                run_rows = list(csv.DictReader(f))
            self.assertEqual("1", run_rows[0]["TP"])
            self.assertEqual("1", run_rows[0]["FP"])
            self.assertEqual("True", run_rows[0]["root_cause_code_match"])

            with (out / "accuracy_summary.csv").open(encoding="utf-8", newline="") as f:
                summary_rows = list(csv.DictReader(f))
            overall = next(item for item in summary_rows if item["scenario"] == "__overall__")
            self.assertAlmostEqual(73.3333333333, float(overall["macro_f1"]))

            report = json.loads((out / "accuracy_summary.json").read_text(encoding="utf-8"))
            self.assertFalse(report["acceptance"]["all_targets_met"])
            self.assertAlmostEqual(80.0, report["totals"]["root_cause_code_accuracy"])
            markdown = (out / "accuracy.md").read_text(encoding="utf-8")
            self.assertIn("同一正例轮次可同时包含 TP 和 FP", markdown)
            self.assertIn("对象 Top-1 正确率", markdown)

    def test_invalid_check_is_infrastructure_error(self) -> None:
        row = self.row(
            "cpu",
            {
                "kind": "positive",
                "passed": False,
                "evaluation_valid": False,
                "report_count": 0,
                "errors": ["decode DiagnosticSession failed"],
            },
        )
        self.assertEqual("infra_error", row["outcome"])
        self.assertEqual(1, row["infra_error"])
        self.assertEqual(0, row["FN"])

    def test_acceptance_requires_and_accepts_ten_round_full_matrix(self) -> None:
        rows: list[dict[str, object]] = []
        for scenario in accuracy.POSITIVE_SCENARIOS:
            for repeat in range(1, 11):
                rows.append(
                    self.row(
                        scenario,
                        positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True),
                        repeat,
                    )
                )
        for scenario in accuracy.NEGATIVE_SCENARIOS:
            for repeat in range(1, 11):
                rows.append(self.row(scenario, negative_check(0), repeat))

        _, totals = accuracy.summarize(rows)
        acceptance = accuracy.acceptance_summary(totals)
        self.assertTrue(totals["positive_ten_round_coverage"])
        self.assertTrue(totals["negative_ten_round_coverage"])
        self.assertTrue(acceptance["coverage_complete"])
        self.assertTrue(acceptance["all_targets_met"])
        self.assertEqual(100.0, totals["macro_f1"])
        self.assertEqual(0.0, totals["negative_false_positive_rate"])

        rows.append(accuracy.classify_run(
            "cpu", positive_check(tp=1, fp=0, type_match=True, code_match=True, object_match=True),
            1, require_status=True,
        ) | {"scenario": "cpu", "repeat": 11})
        _, totals_with_infra = accuracy.summarize(rows)
        self.assertFalse(accuracy.acceptance_summary(totals_with_infra)["all_targets_met"])

    def test_default_repeat_is_ten(self) -> None:
        args = accuracy.build_parser().parse_args([])
        self.assertEqual(10, args.repeat)
        self.assertEqual("deterministic", args.workload)

    def test_default_scenarios_include_strict_negative_matrix(self) -> None:
        expected_negative = (
            "idle",
            "normal_mem",
            "normal_epoll",
            "normal_io_sleep",
            "normal_io_seq",
        )
        self.assertEqual(expected_negative, accuracy.NEGATIVE_SCENARIOS)
        self.assertEqual(
            list(accuracy.POSITIVE_SCENARIOS + expected_negative),
            accuracy.parse_scenarios(["all"]),
        )
        self.assertNotIn("idle_cpu", accuracy.DEFAULT_SCENARIOS)
        self.assertEqual(["idle_cpu"], accuracy.parse_scenarios(["idle_cpu"]))

    def test_legacy_negative_runs_cannot_dilute_primary_fpr(self) -> None:
        rows = [self.row("idle", negative_check(1))]
        rows.extend(self.row("idle_cpu", negative_check(0), repeat) for repeat in range(1, 21))
        _, totals = accuracy.summarize(rows)
        self.assertEqual(100.0, totals["negative_false_positive_rate"])
        self.assertEqual(1, totals["target_negative_valid_runs"])


if __name__ == "__main__":
    unittest.main()
