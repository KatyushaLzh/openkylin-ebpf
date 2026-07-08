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

POSITIVE_SCENARIOS = ("cpu", "io", "mem", "lock", "syscall")
NEGATIVE_SCENARIOS = ("idle_cpu", "idle_io", "idle_lock", "idle_syscall")
DEFAULT_SCENARIOS = POSITIVE_SCENARIOS + NEGATIVE_SCENARIOS
SCENARIO_KIND = {
    **{scenario: "positive" for scenario in POSITIVE_SCENARIOS},
    **{scenario: "negative" for scenario in NEGATIVE_SCENARIOS},
}
OUTCOMES = ("TP", "TN", "FP", "FN", "infra_error")


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
    with path.open(encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError("check.json is not an object")
    return value


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


def classify_run(scenario: str, check: dict[str, Any] | None, command_rc: int | None, error: str = "") -> dict[str, Any]:
    kind = str(check.get("kind") if check else SCENARIO_KIND.get(scenario, "unknown"))
    passed = bool(check.get("passed")) if check else False
    report_count = int_value(check.get("report_count") if check else 0)
    matched_count = list_len(check.get("matched_reports") if check else None)
    extra_count = int_value(check.get("extra_report_count") if check else 0)
    errors = string_list(check.get("errors") if check else [error or "missing check.json"])
    warnings = string_list(check.get("warnings") if check else None)

    if check is None:
        outcome = "infra_error"
        correct = False
        e2e_pass = False
    elif kind == "positive":
        outcome = "TP" if passed and matched_count > 0 else "FN"
        correct = outcome == "TP"
        e2e_pass = correct and command_rc in (0, None)
    elif kind == "negative":
        outcome = "TN" if passed and report_count == 0 else "FP"
        correct = outcome == "TN"
        e2e_pass = correct and command_rc in (0, None)
    else:
        outcome = "infra_error"
        correct = False
        e2e_pass = False
        if not errors:
            errors = f"unknown scenario kind: {kind}"

    return {
        "kind": kind,
        "passed": passed,
        "report_count": report_count,
        "matched_count": matched_count,
        "extra_report_count": extra_count,
        "matched_anomaly_type": str(check.get("matched_anomaly_type", "")) if check else "",
        "truth_summary": str(check.get("truth_summary", "")) if check else "",
        "errors": errors,
        "warnings": warnings,
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

    scenario_from_check = str(check.get("scenario", scenario)) if check else scenario
    row = {
        "scenario": scenario_from_check,
        "repeat": repeat_idx,
        "command_rc": proc.returncode,
        "artifact_dir": str(run_dir),
        "check_path": str(check_path),
        "started_at": started,
        "ended_at": ended,
        "elapsed_sec": f"{elapsed:.3f}",
    }
    row.update(classify_run(scenario_from_check, check, proc.returncode, load_error))
    return row


def repeat_from_path(path: Path) -> int:
    for part in path.parts:
        match = re.search(r"_r([0-9]+)$", part)
        if match:
            return int(match.group(1))
    return 0


def collect_existing(base: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for idx, check_path in enumerate(sorted(base.rglob("check.json")), start=1):
        started = ""
        ended = ""
        try:
            check = load_json(check_path)
            scenario = str(check.get("scenario", check_path.parent.name))
            error = ""
        except Exception as exc:  # noqa: BLE001 - preserve broken artifacts in summary.
            check = None
            scenario = check_path.parent.name
            error = f"read check.json: {exc}"
        repeat_idx = repeat_from_path(check_path)
        if repeat_idx == 0:
            repeat_idx = idx
        row = {
            "scenario": scenario,
            "repeat": repeat_idx,
            "command_rc": "",
            "artifact_dir": str(check_path.parent.parent),
            "check_path": str(check_path),
            "started_at": started,
            "ended_at": ended,
            "elapsed_sec": "",
        }
        row.update(classify_run(scenario, check, None, error))
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


def summarize(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    totals = {outcome: 0 for outcome in OUTCOMES}
    totals.update({"runs": 0, "valid_runs": 0, "correct": 0, "e2e_pass": 0, "extra_reports": 0})

    for scenario in sorted({str(row["scenario"]) for row in rows}):
        items = [row for row in rows if row["scenario"] == scenario]
        counts = {outcome: sum(1 for row in items if row["outcome"] == outcome) for outcome in OUTCOMES}
        runs = len(items)
        valid_runs = runs - counts["infra_error"]
        correct = counts["TP"] + counts["TN"]
        e2e_pass = sum(1 for row in items if row["e2e_pass"])
        extra_counts = [int_value(row["extra_report_count"]) for row in items]
        reports = [int_value(row["report_count"]) for row in items]
        kind = str(items[0].get("kind", SCENARIO_KIND.get(scenario, "unknown"))) if items else "unknown"
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
                "recall": pct(counts["TP"], counts["TP"] + counts["FN"]) if kind == "positive" else None,
                "false_positive_rate": pct(counts["FP"], counts["FP"] + counts["TN"]) if kind == "negative" else None,
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

    totals["diagnostic_accuracy"] = pct(int(totals["correct"]), int(totals["valid_runs"]))
    totals["end_to_end_pass_rate"] = pct(int(totals["e2e_pass"]), int(totals["runs"]))
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
        f.write(f"- 诊断准确率：{fmt_pct(totals['diagnostic_accuracy'])}\n")
        f.write(f"- 端到端通过率：{fmt_pct(totals['end_to_end_pass_rate'])}\n\n")
        f.write("## 1. 统计口径\n\n")
        f.write("- 正例命中：`passed=true` 且 `matched_reports` 非空，记为 TP；否则记为 FN。\n")
        f.write("- 负例命中：`passed=true` 且 `report_count=0`，记为 TN；否则记为 FP。\n")
        f.write("- `check.json` 缺失或无法解析记为 infra_error。\n")
        f.write("- `extra_report_count` 单独统计，不混入 TP/FN。\n\n")
        f.write("## 2. 汇总表\n\n")
        f.write("| 场景 | 类型 | 运行数 | TP | TN | FP | FN | infra | 诊断准确率 | 端到端通过率 | 召回率 | 误报率 | 平均额外报告 |\n")
        f.write("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for item in summaries:
            f.write(
                "| {scenario} | {kind} | {runs} | {TP} | {TN} | {FP} | {FN} | {infra} | {acc} | {e2e} | {recall} | {fpr} | {extra} |\n".format(
                    scenario=item["scenario"],
                    kind=item["kind"],
                    runs=item["runs"],
                    TP=item["TP"],
                    TN=item["TN"],
                    FP=item["FP"],
                    FN=item["FN"],
                    infra=item["infra_error"],
                    acc=fmt_pct(item["diagnostic_accuracy"]),
                    e2e=fmt_pct(item["end_to_end_pass_rate"]),
                    recall=fmt_pct(item["recall"]),
                    fpr=fmt_pct(item["false_positive_rate"]),
                    extra="NA" if item["avg_extra_reports"] is None else f"{item['avg_extra_reports']:.2f}",
                )
            )
        f.write("\n## 3. 图表\n\n")
        f.write("![pass rate](pass_rate_by_scenario.svg)\n\n")
        f.write("![outcome breakdown](error_breakdown.svg)\n\n")
        f.write("## 4. 明细位置\n\n")
        f.write("- 每轮明细：`accuracy_runs.csv`\n")
        f.write("- 汇总 CSV：`accuracy_summary.csv`\n")
        f.write("- 机器可读汇总：`accuracy_summary.json`\n\n")
        failing = [row for row in rows if row["outcome"] in ("FP", "FN", "infra_error") or not row["e2e_pass"]]
        if failing:
            f.write("## 5. 失败/异常轮次\n\n")
            f.write("| 场景 | 轮次 | outcome | command_rc | check | 问题 |\n")
            f.write("|---|---:|---|---:|---|---|\n")
            for row in failing[:50]:
                issue = trim_issue(row.get("errors") or row.get("warnings") or "-")
                f.write(f"| {row['scenario']} | {row['repeat']} | {row['outcome']} | {row['command_rc']} | `{row['check_path']}` | {issue} |\n")
            if len(failing) > 50:
                f.write(f"\n仅展示前 50 条，剩余 {len(failing) - 50} 条见 `accuracy_runs.csv`。\n")
        else:
            f.write("## 5. 失败/异常轮次\n\n无。\n")


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
        "correct",
        "e2e_pass",
        "command_rc",
        "passed",
        "report_count",
        "matched_count",
        "extra_report_count",
        "matched_anomaly_type",
        "truth_summary",
        "artifact_dir",
        "check_path",
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
        "recall",
        "false_positive_rate",
        "avg_extra_reports",
        "avg_report_count",
    ]
    write_csv(out_dir / "accuracy_runs.csv", rows, run_fields)
    write_csv(out_dir / "accuracy_summary.csv", summaries, summary_fields)
    report = {
        "generated_at": generated,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "workload": workload,
        "repeat": repeat,
        "totals": totals,
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
    parser.add_argument("--repeat", type=int, default=3, help="rounds per scenario")
    parser.add_argument("--workload", choices=("stress", "deterministic"), default="stress", help="workload mode passed to test_local.sh")
    parser.add_argument("--duration", help="optional duration passed to test_local.sh")
    parser.add_argument("--out", default="outputs/accuracy", help="output directory")
    parser.add_argument("--no-build", action="store_true", help="skip initial make build/test-checker/test-load")
    parser.add_argument("--from-existing", help="aggregate an existing directory containing check.json files")
    parser.add_argument("--fail-on-miss", action="store_true", help="exit non-zero if any run is not an end-to-end pass")
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
            print("[accuracy] no check.json files found", file=sys.stderr)
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
    print(f"[accuracy] diagnostic_accuracy={fmt_pct(totals['diagnostic_accuracy'])} e2e_pass_rate={fmt_pct(totals['end_to_end_pass_rate'])}")
    if args.fail_on_miss and int(totals["e2e_pass"]) != int(totals["runs"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
