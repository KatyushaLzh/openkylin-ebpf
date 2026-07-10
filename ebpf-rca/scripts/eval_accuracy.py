#!/usr/bin/env python3
"""Run and summarize multi-round ebpf-rca accuracy tests.

The script reuses scripts/test_local.sh for every single E2E run, then
aggregates the produced check.json files into CSV/JSON/Markdown and SVG charts.
It intentionally depends only on the Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from validate_report import strict_json_loads

POSITIVE_SCENARIOS = ("cpu", "io", "mem", "lock", "syscall")
NEGATIVE_SCENARIOS = ("idle", "normal_mem", "normal_epoll", "normal_io_sleep", "normal_io_seq")
LEGACY_NEGATIVE_SCENARIOS = ("idle_cpu", "idle_io", "idle_lock", "idle_syscall")
DEFAULT_SCENARIOS = POSITIVE_SCENARIOS + NEGATIVE_SCENARIOS
SCENARIO_KIND = {
    **{scenario: "positive" for scenario in POSITIVE_SCENARIOS},
    **{scenario: "negative" for scenario in NEGATIVE_SCENARIOS + LEGACY_NEGATIVE_SCENARIOS},
}
OUTCOMES = ("TP", "TN", "FP", "FN", "infra_error")
ACCEPTANCE_TARGETS = {
    "macro_f1_min_pct": 90.0,
    "root_cause_code_accuracy_min_pct": 85.0,
    "object_top1_accuracy_min_pct": 90.0,
    "negative_false_positive_rate_max_pct": 5.0,
    "minimum_valid_rounds_per_class": 10,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_path(root: Path, raw: str | Path) -> Path:
    path = Path(raw)
    if path.is_absolute():
        return path
    return root / path


def parse_scenarios(values: list[str] | None) -> list[str]:
    if not values:
        return list(DEFAULT_SCENARIOS)
    out: list[str] = []
    for value in values:
        for item in value.split(","):
            scenario = item.strip()
            if not scenario:
                continue
            if scenario == "all":
                out.extend(DEFAULT_SCENARIOS)
                continue
            if scenario not in SCENARIO_KIND:
                raise SystemExit(f"unknown scenario {scenario!r}; use all or one of {', '.join(DEFAULT_SCENARIOS)}")
            out.append(scenario)
    deduped: list[str] = []
    seen: set[str] = set()
    for scenario in out:
        if scenario not in seen:
            deduped.append(scenario)
            seen.add(scenario)
    return deduped


def load_json(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("check.json is not an object")
    return value


def load_run_status(path: Path, scenario: str) -> dict[str, Any]:
    status = load_json(path)
    required = {
        "schema_version", "scenario", "complete", "workload_rc", "tool_rc",
        "truth_rc", "health_rc", "checker_rc",
    }
    if set(status) != required:
        raise ValueError(f"run_status fields mismatch: got {sorted(status)}, want {sorted(required)}")
    if status["schema_version"] != "1.0" or status["scenario"] != scenario or status["complete"] is not True:
        raise ValueError("run_status version/scenario/completion mismatch")
    for name in ("workload_rc", "tool_rc", "truth_rc", "health_rc", "checker_rc"):
        value = status[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"run_status {name} must be a non-negative integer")
    return status


def list_len(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def string_list(value: Any) -> str:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    if value is None:
        return ""
    return str(value)


def int_value(value: Any, default: int = 0) -> int:
    try:
        if value in ("", None):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def nonnegative_int(value: Any, default: int = 0) -> int:
    return max(0, int_value(value, default))


def outcome_label(tp: int, tn: int, fp: int, fn: int, infra_error: int) -> str:
    if infra_error:
        return "infra_error"
    labels: list[str] = []
    for label, count in (("TP", tp), ("TN", tn), ("FP", fp), ("FN", fn)):
        if count:
            labels.append(label)
    return "+".join(labels) if labels else "invalid"


def classify_run(
    scenario: str,
    check: dict[str, Any] | None,
    command_rc: int | None,
    error: str = "",
    *,
    run_status: dict[str, Any] | None = None,
    status_error: str = "",
    require_status: bool = False,
) -> dict[str, Any]:
    kind = str(check.get("kind") if check else SCENARIO_KIND.get(scenario, "unknown"))
    passed = bool(check.get("passed")) if check else False
    evaluation_valid = bool(check.get("evaluation_valid", True)) if check else False
    report_count = int_value(check.get("report_count") if check else 0)
    matched_count = list_len(check.get("matched_reports") if check else None)
    extra_count = int_value(check.get("extra_report_count") if check else 0)
    errors = string_list(check.get("errors") if check else [error or "missing check.json"])
    warnings = string_list(check.get("warnings") if check else None)
    top_report = check.get("top_report") if check and isinstance(check.get("top_report"), dict) else {}

    tp = tn = fp = fn = 0
    infra_error = 0
    type_match = False
    code_match = False
    object_match = False

    infrastructure_errors: list[str] = []
    if status_error:
        infrastructure_errors.append(status_error)
    if run_status is None:
        if require_status:
            infrastructure_errors.append("missing run_status.json")
        elif command_rc not in (0, None):
            infrastructure_errors.append(f"command exited with {command_rc} without component status")
    else:
        for name in ("workload_rc", "tool_rc", "truth_rc", "health_rc"):
            if int(run_status[name]) != 0:
                infrastructure_errors.append(f"{name}={run_status[name]}")
        checker_rc = int(run_status["checker_rc"])
        if check is not None and ((checker_rc == 0) != passed):
            infrastructure_errors.append(f"checker_rc={checker_rc} disagrees with check.passed={passed}")
        if command_rc is not None and ((command_rc == 0) != (checker_rc == 0 and not infrastructure_errors)):
            infrastructure_errors.append(f"command_rc={command_rc} disagrees with component status")

    if infrastructure_errors:
        infra_error = 1
        joined = "; ".join(infrastructure_errors)
        errors = f"{errors}; {joined}" if errors else joined
    elif check is None or not evaluation_valid:
        infra_error = 1
    elif kind == "positive":
        # A positive run owns one ground-truth incident. It may therefore have
        # one TP or one FN, while every non-matching report is an independent FP.
        tp = min(1, nonnegative_int(check.get("true_positive"), 1 if matched_count > 0 else 0))
        fn = min(1, nonnegative_int(check.get("false_negative"), 1 - tp))
        fp = nonnegative_int(check.get("false_positive"), extra_count)
        type_match = bool(check.get("type_match", tp > 0))
        code_match = bool(check.get("root_cause_code_match", tp > 0))
        object_match = bool(check.get("workload_object_match", tp > 0))
    elif kind == "negative":
        fp = nonnegative_int(check.get("false_positive"), report_count)
        tn = min(1, nonnegative_int(check.get("true_negative"), 1 if passed and report_count == 0 else 0))
    else:
        infra_error = 1
        if not errors:
            errors = f"unknown scenario kind: {kind}"

    outcome = outcome_label(tp, tn, fp, fn, infra_error)
    correct = infra_error == 0 and ((kind == "positive" and tp == 1 and fn == 0 and fp == 0) or (kind == "negative" and tn == 1 and fp == 0))
    e2e_pass = correct and passed and command_rc in (0, None)

    return {
        "kind": kind,
        "passed": passed,
        "evaluation_valid": evaluation_valid,
        "report_count": report_count,
        "matched_count": matched_count,
        "extra_report_count": extra_count,
        "type_match": type_match,
        "root_cause_code_match": code_match,
        "workload_object_match": object_match,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "infra_error": infra_error,
        "false_positive_run": fp > 0,
        "top_report_index": nonnegative_int(check.get("top_report_index")) if check else 0,
        "top_anomaly_type": str(top_report.get("anomaly_type", "")),
        "top_root_cause_code": str(top_report.get("root_cause_code", "")),
        "top_confidence": top_report.get("confidence", ""),
        "top_object": json.dumps(top_report.get("object", {}), ensure_ascii=False, sort_keys=True) if top_report else "",
        "matched_anomaly_type": str(check.get("matched_anomaly_type", "")) if check else "",
        "truth_summary": str(check.get("truth_summary", "")) if check else "",
        "errors": errors,
        "warnings": warnings,
        "workload_rc": run_status.get("workload_rc", "") if run_status else "",
        "tool_rc": run_status.get("tool_rc", "") if run_status else "",
        "truth_rc": run_status.get("truth_rc", "") if run_status else "",
        "health_rc": run_status.get("health_rc", "") if run_status else "",
        "checker_rc": run_status.get("checker_rc", "") if run_status else "",
        "outcome": outcome,
        "correct": correct,
        "e2e_pass": e2e_pass,
    }


def run_build(root: Path) -> None:
    print("[accuracy] building ebpf-rca, rca-testcheck, and rca-testload", flush=True)
    subprocess.run(["make", "build", "test-checker", "test-load"], cwd=root, check=True)


def run_one(
    root: Path,
    out_dir: Path,
    scenario: str,
    repeat_idx: int,
    workload: str,
    duration: str | None,
) -> dict[str, Any]:
    run_dir = out_dir / "runs" / f"{scenario}_r{repeat_idx}"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "eval_command.log"
    check_path = run_dir / scenario / "check.json"
    status_path = run_dir / scenario / "run_status.json"
    cmd = [
        "bash",
        "scripts/test_local.sh",
        "scenario",
        "--scenario",
        scenario,
        "--out",
        str(run_dir),
        "--workload",
        workload,
        "--no-build",
    ]
    if duration:
        cmd.extend(["--duration", duration])

    started = utc_now()
    t0 = time.monotonic()
    print(f"[accuracy] scenario={scenario} repeat={repeat_idx} workload={workload}", flush=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        proc = subprocess.run(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT)
    elapsed = time.monotonic() - t0
    ended = utc_now()

    check: dict[str, Any] | None = None
    load_error = ""
    if check_path.exists():
        try:
            check = load_json(check_path)
        except Exception as exc:  # noqa: BLE001 - report parse failures as data.
            load_error = f"read check.json: {exc}"
    else:
        load_error = "missing check.json"

    run_status: dict[str, Any] | None = None
    status_error = ""
    if status_path.exists():
        try:
            run_status = load_run_status(status_path, scenario)
        except Exception as exc:  # noqa: BLE001 - invalid status is infrastructure evidence.
            status_error = f"read run_status.json: {exc}"
    else:
        status_error = "missing run_status.json"

    scenario_from_check = str(check.get("scenario", scenario)) if check else scenario
    row = {
        "scenario": scenario_from_check,
        "repeat": repeat_idx,
        "command_rc": proc.returncode,
        "artifact_dir": str(run_dir),
        "check_path": str(check_path),
        "status_path": str(status_path),
        "started_at": started,
        "ended_at": ended,
        "elapsed_sec": f"{elapsed:.3f}",
    }
    row.update(classify_run(
        scenario_from_check, check, proc.returncode, load_error,
        run_status=run_status, status_error=status_error, require_status=True,
    ))
    return row


def repeat_from_path(path: Path) -> int:
    for part in path.parts:
        match = re.search(r"_r([0-9]+)$", part)
        if match:
            return int(match.group(1))
    return 0


def collect_existing(base: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    artifact_dirs = {path.parent for path in base.rglob("check.json")}
    artifact_dirs.update(path.parent for path in base.rglob("run_status.json"))
    for idx, artifact_dir in enumerate(sorted(artifact_dirs), start=1):
        check_path = artifact_dir / "check.json"
        status_path = artifact_dir / "run_status.json"
        started = ""
        ended = ""
        check: dict[str, Any] | None = None
        scenario = artifact_dir.name
        error = ""
        if check_path.exists():
            try:
                check = load_json(check_path)
                scenario = str(check.get("scenario", scenario))
            except Exception as exc:  # noqa: BLE001 - preserve broken artifacts in summary.
                error = f"read check.json: {exc}"
        else:
            error = "missing check.json"
        repeat_idx = repeat_from_path(artifact_dir)
        if repeat_idx == 0:
            repeat_idx = idx
        run_status: dict[str, Any] | None = None
        status_error = ""
        if status_path.exists():
            try:
                run_status = load_run_status(status_path, scenario)
                scenario = str(run_status["scenario"])
            except Exception as exc:  # noqa: BLE001 - preserve invalid artifacts.
                status_error = f"read run_status.json: {exc}"
        else:
            status_error = "missing run_status.json"
        command_rc: int | None = None
        if run_status is not None:
            component_names = ("workload_rc", "tool_rc", "truth_rc", "health_rc", "checker_rc")
            command_rc = 0 if all(int(run_status[name]) == 0 for name in component_names) else 1
        row = {
            "scenario": scenario,
            "repeat": repeat_idx,
            "command_rc": "" if command_rc is None else command_rc,
            "artifact_dir": str(artifact_dir.parent),
            "check_path": str(check_path),
            "status_path": str(status_path),
            "started_at": started,
            "ended_at": ended,
            "elapsed_sec": "",
        }
        row.update(classify_run(
            scenario, check, command_rc, error,
            run_status=run_status, status_error=status_error, require_status=True,
        ))
        rows.append(row)
    return rows


def pct(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator * 100.0


def fmt_pct(value: float | None) -> str:
    return "NA" if value is None else f"{value:.1f}%"


def trim_issue(text: Any, limit: int = 360) -> str:
    issue = str(text or "-").replace("\n", " ")
    if len(issue) <= limit:
        return issue
    return issue[: limit - 16].rstrip() + " ...[truncated]"


def mean(values: list[float]) -> float | None:
    return None if not values else sum(values) / len(values)


def f1_pct(tp: int, fp: int, fn: int) -> float | None:
    denominator = 2 * tp + fp + fn
    if denominator == 0:
        return None
    return 2 * tp / denominator * 100.0


def summarize(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    totals = {outcome: 0 for outcome in OUTCOMES}
    totals.update(
        {
            "runs": 0,
            "valid_runs": 0,
            "correct": 0,
            "e2e_pass": 0,
            "extra_reports": 0,
            "false_positive_runs": 0,
            "positive_valid_runs": 0,
            "negative_valid_runs": 0,
            "type_matches": 0,
            "root_cause_code_matches": 0,
            "object_top1_matches": 0,
        }
    )

    for scenario in sorted({str(row["scenario"]) for row in rows}):
        items = [row for row in rows if row["scenario"] == scenario]
        counts = {outcome: sum(nonnegative_int(row.get(outcome)) for row in items) for outcome in OUTCOMES}
        runs = len(items)
        valid_runs = sum(1 for row in items if not nonnegative_int(row.get("infra_error")))
        correct = sum(1 for row in items if row["correct"])
        e2e_pass = sum(1 for row in items if row["e2e_pass"])
        false_positive_runs = sum(1 for row in items if row.get("false_positive_run") and not nonnegative_int(row.get("infra_error")))
        extra_counts = [int_value(row["extra_report_count"]) for row in items]
        reports = [int_value(row["report_count"]) for row in items]
        kind = str(items[0].get("kind", SCENARIO_KIND.get(scenario, "unknown"))) if items else "unknown"
        type_matches = sum(1 for row in items if row.get("type_match") and not nonnegative_int(row.get("infra_error")))
        code_matches = sum(1 for row in items if row.get("root_cause_code_match") and not nonnegative_int(row.get("infra_error")))
        object_matches = sum(1 for row in items if row.get("workload_object_match") and not nonnegative_int(row.get("infra_error")))
        summaries.append(
            {
                "scenario": scenario,
                "kind": kind,
                "runs": runs,
                "valid_runs": valid_runs,
                "TP": counts["TP"],
                "TN": counts["TN"],
                "FP": counts["FP"],
                "FN": counts["FN"],
                "infra_error": counts["infra_error"],
                "diagnostic_accuracy": pct(correct, valid_runs),
                "end_to_end_pass_rate": pct(e2e_pass, runs),
                "precision": (pct(counts["TP"], counts["TP"] + counts["FP"]) or 0.0) if kind == "positive" and valid_runs > 0 else None,
                "recall": pct(counts["TP"], counts["TP"] + counts["FN"]) if kind == "positive" else None,
                "f1": f1_pct(counts["TP"], counts["FP"], counts["FN"]) if kind == "positive" else None,
                "type_accuracy": pct(type_matches, valid_runs) if kind == "positive" else None,
                "root_cause_code_accuracy": pct(code_matches, valid_runs) if kind == "positive" else None,
                "object_top1_accuracy": pct(object_matches, valid_runs) if kind == "positive" else None,
                "false_positive_runs": false_positive_runs,
                "false_positive_rate": pct(false_positive_runs, valid_runs) if kind == "negative" else None,
                "negative_false_positive_rate": pct(false_positive_runs, valid_runs) if kind == "negative" else None,
                "avg_extra_reports": mean(extra_counts),
                "avg_report_count": mean(reports),
            }
        )
        for key in OUTCOMES:
            totals[key] += counts[key]
        totals["runs"] += runs
        totals["valid_runs"] += valid_runs
        totals["correct"] += correct
        totals["e2e_pass"] += e2e_pass
        totals["extra_reports"] += sum(extra_counts)
        totals["false_positive_runs"] += false_positive_runs
        if kind == "positive":
            totals["positive_valid_runs"] += valid_runs
            totals["type_matches"] += type_matches
            totals["root_cause_code_matches"] += code_matches
            totals["object_top1_matches"] += object_matches
        elif kind == "negative":
            totals["negative_valid_runs"] += valid_runs

    totals["diagnostic_accuracy"] = pct(int(totals["correct"]), int(totals["valid_runs"]))
    totals["end_to_end_pass_rate"] = pct(int(totals["e2e_pass"]), int(totals["runs"]))
    positive_summaries = [item for item in summaries if item["kind"] == "positive" and item["scenario"] in POSITIVE_SCENARIOS]
    observed_positive_classes = {str(item["scenario"]) for item in positive_summaries if int(item["valid_runs"]) > 0}
    totals["positive_classes_expected"] = len(POSITIVE_SCENARIOS)
    totals["positive_classes_evaluated"] = len(observed_positive_classes)
    totals["five_positive_classes_complete"] = observed_positive_classes == set(POSITIVE_SCENARIOS)
    positive_rounds = {str(item["scenario"]): int(item["valid_runs"]) for item in positive_summaries}
    totals["positive_ten_round_coverage"] = all(positive_rounds.get(scenario, 0) >= 10 for scenario in POSITIVE_SCENARIOS)
    totals["macro_precision"] = mean([float(item["precision"]) for item in positive_summaries if item["precision"] is not None])
    totals["macro_recall"] = mean([float(item["recall"]) for item in positive_summaries if item["recall"] is not None])
    totals["macro_f1"] = mean([float(item["f1"]) for item in positive_summaries if item["f1"] is not None])
    totals["type_accuracy"] = pct(int(totals["type_matches"]), int(totals["positive_valid_runs"]))
    totals["root_cause_code_accuracy"] = pct(int(totals["root_cause_code_matches"]), int(totals["positive_valid_runs"]))
    totals["object_top1_accuracy"] = pct(int(totals["object_top1_matches"]), int(totals["positive_valid_runs"]))
    negative_summaries = [item for item in summaries if item["kind"] == "negative" and item["scenario"] in NEGATIVE_SCENARIOS]
    negative_fp_runs = sum(int(item["false_positive_runs"]) for item in negative_summaries)
    target_negative_valid_runs = sum(int(item["valid_runs"]) for item in negative_summaries)
    observed_negative_classes = {str(item["scenario"]) for item in negative_summaries if int(item["valid_runs"]) > 0}
    negative_rounds = {str(item["scenario"]): int(item["valid_runs"]) for item in negative_summaries}
    totals["negative_classes_expected"] = len(NEGATIVE_SCENARIOS)
    totals["negative_classes_evaluated"] = len(observed_negative_classes)
    totals["negative_ten_round_coverage"] = all(negative_rounds.get(scenario, 0) >= 10 for scenario in NEGATIVE_SCENARIOS)
    totals["negative_false_positive_runs"] = negative_fp_runs
    totals["target_negative_valid_runs"] = target_negative_valid_runs
    totals["negative_false_positive_rate"] = pct(negative_fp_runs, target_negative_valid_runs)
    return summaries, totals


def observed_repeat(rows: list[dict[str, Any]]) -> int:
    counts: dict[str, int] = {}
    for row in rows:
        scenario = str(row.get("scenario", ""))
        if not scenario:
            continue
        counts[scenario] = counts.get(scenario, 0) + 1
    return max(counts.values(), default=0)


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def svg_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_bar_svg(
    path: Path,
    title: str,
    labels: list[str],
    values: list[float],
    *,
    ymax: float,
    unit: str,
    color: str = "#2f80ed",
) -> None:
    width = max(720, 120 + len(labels) * 70)
    height = 360
    left = 64
    right = 24
    top = 52
    bottom = 76
    chart_w = width - left - right
    chart_h = height - top - bottom
    gap = 18
    bar_w = max(24, (chart_w - gap * (len(labels) + 1)) / max(len(labels), 1))

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2:.1f}" y="28" text-anchor="middle" font-family="sans-serif" font-size="18" font-weight="700">{svg_escape(title)}</text>',
        f'<line x1="{left}" y1="{top + chart_h}" x2="{width - right}" y2="{top + chart_h}" stroke="#222" stroke-width="1"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + chart_h}" stroke="#222" stroke-width="1"/>',
    ]
    for tick in range(0, 6):
        value = ymax * tick / 5
        y = top + chart_h - chart_h * tick / 5
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="#e6e6e6" stroke-width="1"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" font-family="sans-serif" font-size="11" fill="#444">{value:.0f}{unit}</text>')

    for idx, (label, raw_value) in enumerate(zip(labels, values)):
        value = max(0.0, min(raw_value, ymax))
        x = left + gap + idx * (bar_w + gap)
        bar_h = chart_h * value / ymax if ymax else 0
        y = top + chart_h - bar_h
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" fill="{color}" rx="3"/>')
        parts.append(f'<text x="{x + bar_w / 2:.1f}" y="{y - 6:.1f}" text-anchor="middle" font-family="sans-serif" font-size="11" fill="#222">{raw_value:.1f}{unit}</text>')
        parts.append(f'<text x="{x + bar_w / 2:.1f}" y="{top + chart_h + 22}" text-anchor="middle" font-family="sans-serif" font-size="12" fill="#222">{svg_escape(label)}</text>')

    parts.append("</svg>\n")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_outcome_svg(path: Path, totals: dict[str, Any]) -> None:
    labels = list(OUTCOMES)
    values = [float(totals.get(label, 0)) for label in labels]
    ymax = max(values + [1.0])
    write_bar_svg(path, "Outcome breakdown", labels, values, ymax=ymax, unit="", color="#27ae60")


def acceptance_summary(totals: dict[str, Any]) -> dict[str, Any]:
    coverage_complete = bool(totals.get("positive_ten_round_coverage")) and bool(totals.get("negative_ten_round_coverage"))
    infrastructure_clean = int(totals.get("infra_error", 0)) == 0
    checks = {
        "macro_f1": {
            "value_pct": totals.get("macro_f1"),
            "target_min_pct": ACCEPTANCE_TARGETS["macro_f1_min_pct"],
        },
        "root_cause_code_accuracy": {
            "value_pct": totals.get("root_cause_code_accuracy"),
            "target_min_pct": ACCEPTANCE_TARGETS["root_cause_code_accuracy_min_pct"],
        },
        "object_top1_accuracy": {
            "value_pct": totals.get("object_top1_accuracy"),
            "target_min_pct": ACCEPTANCE_TARGETS["object_top1_accuracy_min_pct"],
        },
        "negative_false_positive_rate": {
            "value_pct": totals.get("negative_false_positive_rate"),
            "target_max_pct": ACCEPTANCE_TARGETS["negative_false_positive_rate_max_pct"],
        },
    }
    for name, check in checks.items():
        value = check["value_pct"]
        if value is None:
            check["passed"] = None
        elif name == "negative_false_positive_rate":
            check["passed"] = float(value) <= float(check["target_max_pct"])
        else:
            check["passed"] = float(value) >= float(check["target_min_pct"])
    return {
        "coverage_complete": coverage_complete,
        "infrastructure_clean": infrastructure_clean,
        "minimum_valid_rounds_per_class": ACCEPTANCE_TARGETS["minimum_valid_rounds_per_class"],
        "all_targets_met": coverage_complete and infrastructure_clean and all(check["passed"] is True for check in checks.values()),
        "metrics": checks,
    }


def write_markdown(
    path: Path,
    generated: str,
    workload: str,
    repeat: int,
    rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    totals: dict[str, Any],
) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write("# ebpf-rca 多轮准确率评测报告\n\n")
        f.write(f"- 生成时间：{generated}\n")
        f.write(f"- Kernel：{platform.release()}\n")
        f.write(f"- 架构：{platform.machine()}\n")
        f.write(f"- workload：`{workload}`\n")
        f.write(f"- repeat：{repeat}\n")
        f.write(f"- 总运行数：{totals['runs']}，有效运行数：{totals['valid_runs']}\n")
        f.write(f"- 五类正例 macro-F1：{fmt_pct(totals['macro_f1'])}\n")
        f.write(f"- 根因 code 正确率：{fmt_pct(totals['root_cause_code_accuracy'])}\n")
        f.write(f"- 对象 Top-1 正确率：{fmt_pct(totals['object_top1_accuracy'])}\n")
        f.write(f"- 负例轮次误报率：{fmt_pct(totals['negative_false_positive_rate'])}\n")
        f.write(f"- 端到端通过率：{fmt_pct(totals['end_to_end_pass_rate'])}\n\n")
        f.write("## 1. 统计口径\n\n")
        f.write("- 正例每轮只有一个真实 incident：存在完整匹配报告记 1 TP，否则记 1 FN。\n")
        f.write("- 同一正例轮次可同时包含 TP 和 FP；每个不完整匹配的报告各记 1 FP。\n")
        f.write("- 类型、root-cause code、对象命中均绑定同一个 Top-1 报告：按 confidence 最高选择，同分取最早报告。\n")
        f.write("- 负例每个报告各记 1 FP；零报告记 1 TN。负例误报率按“出现至少一个 FP 的轮次/有效负例轮次”计算。\n")
        f.write("- `check.json`/`run_status.json` 缺失、严格解析失败，或 tool/workload/truth/health 任一非零，记为 infra_error。\n")
        f.write("- strict E2E 只有 `TP=1 && FP=0`（负例为 `TN=1 && FP=0`）且命令成功才通过。\n\n")
        f.write("## 2. 汇总表\n\n")
        f.write("| 场景 | 类型 | 运行数 | TP | TN | FP | FN | infra | Precision | Recall | F1 | code | 对象 Top-1 | 负例误报率 | E2E |\n")
        f.write("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for item in summaries:
            f.write(
                "| {scenario} | {kind} | {runs} | {TP} | {TN} | {FP} | {FN} | {infra} | {precision} | {recall} | {f1} | {code} | {obj} | {fpr} | {e2e} |\n".format(
                    scenario=item["scenario"],
                    kind=item["kind"],
                    runs=item["runs"],
                    TP=item["TP"],
                    TN=item["TN"],
                    FP=item["FP"],
                    FN=item["FN"],
                    infra=item["infra_error"],
                    precision=fmt_pct(item["precision"]),
                    e2e=fmt_pct(item["end_to_end_pass_rate"]),
                    recall=fmt_pct(item["recall"]),
                    f1=fmt_pct(item["f1"]),
                    code=fmt_pct(item["root_cause_code_accuracy"]),
                    obj=fmt_pct(item["object_top1_accuracy"]),
                    fpr=fmt_pct(item["false_positive_rate"]),
                )
            )
        acceptance = acceptance_summary(totals)
        acceptance_status = "PASS" if acceptance["all_targets_met"] else ("FAIL" if acceptance["coverage_complete"] else "NOT EVALUATED")
        f.write("\n## 3. 验收指标\n\n")
        f.write(f"- 五类正例覆盖完整：{'是' if totals['five_positive_classes_complete'] else '否'}（{totals['positive_classes_evaluated']}/{totals['positive_classes_expected']}）\n")
        f.write(f"- 每类至少 10 个有效轮次：正例 {'是' if totals['positive_ten_round_coverage'] else '否'}；负例 {'是' if totals['negative_ten_round_coverage'] else '否'}\n")
        f.write(f"- 基础设施错误为 0：{'是' if acceptance['infrastructure_clean'] else '否'}（infra_error={totals['infra_error']}）\n")
        f.write(f"- macro precision / recall / F1：{fmt_pct(totals['macro_precision'])} / {fmt_pct(totals['macro_recall'])} / {fmt_pct(totals['macro_f1'])}\n")
        f.write(f"- macro-F1 >= 90%：{fmt_pct(totals['macro_f1'])}\n")
        f.write(f"- root-cause code accuracy >= 85%：{fmt_pct(totals['root_cause_code_accuracy'])}\n")
        f.write(f"- object Top-1 accuracy >= 90%：{fmt_pct(totals['object_top1_accuracy'])}\n")
        f.write(f"- negative false-positive rate <= 5%：{fmt_pct(totals['negative_false_positive_rate'])}\n")
        f.write(f"- 完整覆盖下全部达标：{acceptance_status}\n")
        f.write("\n## 4. 图表\n\n")
        f.write("![pass rate](pass_rate_by_scenario.svg)\n\n")
        f.write("![outcome breakdown](error_breakdown.svg)\n\n")
        f.write("## 5. 明细位置\n\n")
        f.write("- 每轮明细：`accuracy_runs.csv`\n")
        f.write("- 汇总 CSV：`accuracy_summary.csv`\n")
        f.write("- 机器可读汇总：`accuracy_summary.json`\n\n")
        failing = [row for row in rows if not row["e2e_pass"]]
        if failing:
            f.write("## 6. 失败/异常轮次\n\n")
            f.write("| 场景 | 轮次 | outcome | command_rc | check | 问题 |\n")
            f.write("|---|---:|---|---:|---|---|\n")
            for row in failing[:50]:
                issue = trim_issue(row.get("errors") or row.get("warnings") or "-")
                f.write(f"| {row['scenario']} | {row['repeat']} | {row['outcome']} | {row['command_rc']} | `{row['check_path']}` | {issue} |\n")
            if len(failing) > 50:
                f.write(f"\n仅展示前 50 条，剩余 {len(failing) - 50} 条见 `accuracy_runs.csv`。\n")
        else:
            f.write("## 6. 失败/异常轮次\n\n无。\n")


def write_outputs(
    out_dir: Path,
    rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    totals: dict[str, Any],
    workload: str,
    repeat: int,
) -> None:
    generated = utc_now()
    run_fields = [
        "scenario",
        "repeat",
        "kind",
        "outcome",
        "TP",
        "TN",
        "FP",
        "FN",
        "infra_error",
        "correct",
        "e2e_pass",
        "command_rc",
        "workload_rc",
        "tool_rc",
        "truth_rc",
        "health_rc",
        "checker_rc",
        "passed",
        "evaluation_valid",
        "report_count",
        "matched_count",
        "extra_report_count",
        "false_positive_run",
        "type_match",
        "root_cause_code_match",
        "workload_object_match",
        "top_report_index",
        "top_anomaly_type",
        "top_root_cause_code",
        "top_confidence",
        "top_object",
        "matched_anomaly_type",
        "truth_summary",
        "artifact_dir",
        "check_path",
        "status_path",
        "started_at",
        "ended_at",
        "elapsed_sec",
        "errors",
        "warnings",
    ]
    summary_fields = [
        "scenario",
        "kind",
        "runs",
        "valid_runs",
        "TP",
        "TN",
        "FP",
        "FN",
        "infra_error",
        "diagnostic_accuracy",
        "end_to_end_pass_rate",
        "precision",
        "recall",
        "f1",
        "type_accuracy",
        "root_cause_code_accuracy",
        "object_top1_accuracy",
        "false_positive_runs",
        "false_positive_rate",
        "negative_false_positive_rate",
        "avg_extra_reports",
        "avg_report_count",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "five_positive_classes_complete",
    ]
    write_csv(out_dir / "accuracy_runs.csv", rows, run_fields)
    csv_summaries = list(summaries)
    csv_summaries.append(
        {
            "scenario": "__overall__",
            "kind": "overall",
            "runs": totals["runs"],
            "valid_runs": totals["valid_runs"],
            "TP": totals["TP"],
            "TN": totals["TN"],
            "FP": totals["FP"],
            "FN": totals["FN"],
            "infra_error": totals["infra_error"],
            "diagnostic_accuracy": totals["diagnostic_accuracy"],
            "end_to_end_pass_rate": totals["end_to_end_pass_rate"],
            "type_accuracy": totals["type_accuracy"],
            "root_cause_code_accuracy": totals["root_cause_code_accuracy"],
            "object_top1_accuracy": totals["object_top1_accuracy"],
            "false_positive_runs": totals["false_positive_runs"],
            "false_positive_rate": totals["negative_false_positive_rate"],
            "negative_false_positive_rate": totals["negative_false_positive_rate"],
            "macro_precision": totals["macro_precision"],
            "macro_recall": totals["macro_recall"],
            "macro_f1": totals["macro_f1"],
            "five_positive_classes_complete": totals["five_positive_classes_complete"],
        }
    )
    write_csv(out_dir / "accuracy_summary.csv", csv_summaries, summary_fields)
    report = {
        "generated_at": generated,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "workload": workload,
        "repeat": repeat,
        "totals": totals,
        "acceptance": acceptance_summary(totals),
        "summary": summaries,
        "raw_csv": "accuracy_runs.csv",
    }
    (out_dir / "accuracy_summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    labels = [str(item["scenario"]) for item in summaries]
    values = [float(item["end_to_end_pass_rate"] or 0.0) for item in summaries]
    write_bar_svg(out_dir / "pass_rate_by_scenario.svg", "End-to-end pass rate by scenario", labels, values, ymax=100.0, unit="%")
    write_outcome_svg(out_dir / "error_breakdown.svg", totals)
    write_markdown(out_dir / "accuracy.md", generated, workload, repeat, rows, summaries, totals)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run multi-round ebpf-rca accuracy evaluation.")
    parser.add_argument("--scenario", action="append", help="scenario, comma list, or all; repeatable")
    parser.add_argument("--repeat", type=int, default=10, help="rounds per scenario (default: 10)")
    parser.add_argument(
        "--workload",
        choices=("stress", "deterministic"),
        default="deterministic",
        help="workload mode passed to test_local.sh (default: deterministic; stress is supplementary)",
    )
    parser.add_argument("--duration", help="optional duration passed to test_local.sh")
    parser.add_argument("--out", default="outputs/accuracy", help="output directory")
    parser.add_argument("--no-build", action="store_true", help="skip initial make build/test-checker/test-load")
    parser.add_argument("--from-existing", help="aggregate an existing directory containing check.json files")
    parser.add_argument("--fail-on-miss", action="store_true", help="exit non-zero if any run is not an end-to-end pass")
    parser.add_argument(
        "--require-acceptance",
        action="store_true",
        help="exit non-zero unless every class has >=10 valid rounds and all published accuracy targets pass",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    root = repo_root()
    out_dir = resolve_path(root, args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = parse_scenarios(args.scenario)
    if args.from_existing:
        rows = collect_existing(resolve_path(root, args.from_existing))
        if not rows:
            print("[accuracy] no check.json or run_status.json artifacts found", file=sys.stderr)
            return 1
        effective_repeat = observed_repeat(rows)
    else:
        if not args.no_build:
            run_build(root)
        rows = []
        for scenario in scenarios:
            for repeat_idx in range(1, args.repeat + 1):
                rows.append(run_one(root, out_dir, scenario, repeat_idx, args.workload, args.duration))
        effective_repeat = args.repeat

    summaries, totals = summarize(rows)
    write_outputs(out_dir, rows, summaries, totals, args.workload, effective_repeat)
    print(f"[accuracy] wrote {out_dir / 'accuracy.md'}")
    print(
        "[accuracy] "
        f"macro_f1={fmt_pct(totals['macro_f1'])} "
        f"root_cause_code_accuracy={fmt_pct(totals['root_cause_code_accuracy'])} "
        f"object_top1_accuracy={fmt_pct(totals['object_top1_accuracy'])} "
        f"negative_fpr={fmt_pct(totals['negative_false_positive_rate'])} "
        f"e2e_pass_rate={fmt_pct(totals['end_to_end_pass_rate'])}"
    )
    if args.fail_on_miss and int(totals["e2e_pass"]) != int(totals["runs"]):
        return 1
    if args.require_acceptance and not acceptance_summary(totals)["all_targets_met"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
