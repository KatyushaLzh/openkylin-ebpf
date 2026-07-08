#!/usr/bin/env python3
"""Validate ebpf-rca structured report artifacts.

The tool accepts normal JSON, JSON arrays, JSON Lines, and the stream produced
by json.Encoder.SetIndent: multiple pretty-printed JSON objects concatenated in
one file. Every report object in a file is checked, not just the last one.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

REQUIRED = [
    "anomaly_type",
    "related_object",
    "key_metrics",
    "time_window",
    "suspected_root_cause",
    "evidence_chain",
    "suggestion",
]
OPTIONAL_BUT_IMPORTANT = ["confidence"]

ROOT_CAUSE_KEYWORDS = {
    "cpu": ["CPU", "计算", "busy", "热点", "饱和", "调度"],
    "io": ["I/O", "IO", "队列", "P99", "时延", "延迟", "吞吐", "设备"],
    "mem": ["内存", "reclaim", "kswapd", "缺页", "OOM", "回收"],
    "lock": ["锁", "futex", "mutex", "off-CPU", "阻塞", "唤醒"],
    "syscall": ["syscall", "系统调用", "read", "write", "fsync", "poll"],
}


def decode_json_values(text: str) -> list[Any]:
    """Decode all top-level JSON values from possibly noisy text."""
    text = text.strip()
    if not text:
        raise ValueError("empty file")

    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    values: list[Any] = []
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        if text[i] not in "{[":
            next_obj = min(
                [pos for pos in (text.find("{", i + 1), text.find("[", i + 1)) if pos != -1],
                default=-1,
            )
            if next_obj == -1:
                break
            i = next_obj
        try:
            value, end = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            i += 1
            continue
        values.append(value)
        i = end

    if values:
        return values

    # Last chance for logs containing one JSON object/array block.
    match = re.search(r"(\{.*\}|\[.*\])", text, re.S)
    if match:
        return [json.loads(match.group(1))]
    raise ValueError("no JSON object or array found")


def load_json_lenient(path: Path) -> list[Any]:
    return decode_json_values(path.read_text(encoding="utf-8", errors="replace"))


def iter_reports(values: list[Any]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for value in values:
        if isinstance(value, list):
            reports.extend(x for x in value if isinstance(x, dict))
        elif isinstance(value, dict):
            reports.append(value)
    return reports


def has_any_key(obj: Any, keys: list[str]) -> bool:
    return isinstance(obj, dict) and any(k in obj and obj[k] not in (None, "", []) for k in keys)


def numeric_metric_count(obj: Any) -> int:
    count = 0
    if isinstance(obj, dict):
        for value in obj.values():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                count += 1
            elif isinstance(value, dict):
                count += numeric_metric_count(value)
            elif isinstance(value, list):
                count += sum(numeric_metric_count(x) for x in value)
    return count


def infer_scenario(path: Path, report: dict[str, Any]) -> str:
    name = path.name.lower()
    typ = str(report.get("anomaly_type", "")).lower()
    root = str(report.get("suspected_root_cause", "")).lower()
    text = f"{name} {typ} {root}"

    for scenario in ("lock", "syscall", "mem", "io", "cpu"):
        if name.startswith(f"{scenario}_") or name.startswith(f"{scenario}-"):
            return scenario
    if "锁" in typ or "futex" in text or "mutex" in text:
        return "lock"
    if "系统调用" in typ or "syscall" in typ:
        return "syscall"
    if "内存" in typ or "reclaim" in text:
        return "mem"
    if "i/o" in typ or typ.startswith("io") or "延迟" in typ:
        return "io"
    if "cpu" in typ or "计算" in typ:
        return "cpu"

    for scenario in ("lock", "syscall", "mem", "io", "cpu"):
        if scenario in text:
            return scenario
    if "i/o" in text or "io" in text:
        return "io"
    if "内存" in text or "reclaim" in text:
        return "mem"
    if "锁" in text or "futex" in text or "mutex" in text:
        return "lock"
    if "系统调用" in text:
        return "syscall"
    return "unknown"


def check_one(path: Path, idx: int, report: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warns: list[str] = []
    score = 100

    for field in REQUIRED:
        if field not in report or report[field] in (None, "", [], {}):
            errors.append(f"missing_required:{field}")
            score -= 12

    for field in OPTIONAL_BUT_IMPORTANT:
        if field not in report or report[field] in (None, ""):
            warns.append(f"missing_optional:{field}")
            score -= 3

    related = report.get("related_object")
    if not has_any_key(related, ["pid", "tid", "comm", "process", "device", "dev", "syscall"]):
        errors.append("related_object_no_identifiable_target")
        score -= 8

    metrics = report.get("key_metrics")
    if numeric_metric_count(metrics) == 0:
        errors.append("key_metrics_no_numeric_metric")
        score -= 8

    time_window = report.get("time_window")
    if not has_any_key(time_window, ["start"]) or not has_any_key(time_window, ["end"]):
        errors.append("time_window_missing_start_or_end")
        score -= 8

    evidence = report.get("evidence_chain")
    ev_len = len(evidence) if isinstance(evidence, list) else 0
    if ev_len == 0:
        errors.append("empty_evidence_chain")
        score -= 15
    else:
        weak = 0
        for item in evidence:
            if not isinstance(item, dict):
                weak += 1
                continue
            if not any(k in item for k in ("type", "name", "desc", "func", "value")):
                weak += 1
        if weak:
            warns.append(f"weak_evidence_items:{weak}")
            score -= min(weak * 2, 8)

    conf = report.get("confidence")
    if conf is not None:
        try:
            c = float(conf)
            if not 0 <= c <= 1:
                errors.append("confidence_out_of_range")
                score -= 5
        except Exception:
            errors.append("confidence_not_number")
            score -= 5

    scenario = infer_scenario(path, report)
    root_text = str(report.get("suspected_root_cause", "")) + " " + str(report.get("anomaly_type", ""))
    if scenario in ROOT_CAUSE_KEYWORDS:
        if not any(keyword.lower() in root_text.lower() for keyword in ROOT_CAUSE_KEYWORDS[scenario]):
            warns.append("root_cause_wording_not_close_to_expected_scenario")
            score -= 5

    score = max(0, score)
    return {
        "file": str(path),
        "report_index": idx,
        "scenario": scenario,
        "score": score,
        "status": "PASS" if not errors and score >= 85 else ("WARN" if score >= 70 else "FAIL"),
        "missing_required": ";".join(x for x in errors if x.startswith("missing_required")),
        "errors": ";".join(errors),
        "warnings": ";".join(warns),
        "evidence_len": ev_len,
        "anomaly_type": str(report.get("anomaly_type", "")),
        "root_cause": str(report.get("suspected_root_cause", "")),
    }


def failure_row(path: Path, exc: Exception) -> dict[str, Any]:
    return {
        "file": str(path),
        "report_index": 0,
        "scenario": "unknown",
        "score": 0,
        "status": "FAIL",
        "missing_required": ";".join(REQUIRED),
        "errors": f"json_load_error:{exc}",
        "warnings": "",
        "evidence_len": 0,
        "anomaly_type": "",
        "root_cause": "",
    }


def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: python3 scripts/validate_report.py outputs/repro/*.json", file=sys.stderr)
        return 2

    out_dir = Path("outputs/validation")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "schema_check.csv"
    md_path = out_dir / "schema_check.md"
    rows: list[dict[str, Any]] = []

    for raw in argv:
        path = Path(raw)
        try:
            values = load_json_lenient(path)
            reports = iter_reports(values)
            if not reports:
                raise ValueError("no report object found")
            for idx, report in enumerate(reports):
                rows.append(check_one(path, idx, report))
        except Exception as exc:
            rows.append(failure_row(path, exc))

    fields = [
        "file",
        "report_index",
        "scenario",
        "status",
        "score",
        "evidence_len",
        "missing_required",
        "errors",
        "warnings",
        "anomaly_type",
        "root_cause",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    by_scenario: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_scenario.setdefault(str(row["scenario"]), []).append(row)

    with md_path.open("w", encoding="utf-8") as f:
        f.write("# ebpf-rca 结构化输出校验报告\n\n")
        f.write("本报告检查 JSON 输出是否满足评分细则里的结构化输出与证据链要求。\n\n")
        f.write("## 汇总\n\n")
        f.write("| 场景 | 报告数 | PASS | WARN | FAIL | 平均分 |\n")
        f.write("|---|---:|---:|---:|---:|---:|\n")
        for scenario, items in sorted(by_scenario.items()):
            avg = sum(float(x["score"]) for x in items) / len(items)
            f.write(
                f"| {scenario} | {len(items)} | "
                f"{sum(1 for x in items if x['status'] == 'PASS')} | "
                f"{sum(1 for x in items if x['status'] == 'WARN')} | "
                f"{sum(1 for x in items if x['status'] == 'FAIL')} | {avg:.1f} |\n"
            )
        f.write("\n## 明细\n\n")
        f.write("| 文件 | 序号 | 场景 | 状态 | 分数 | 证据条数 | 问题 |\n")
        f.write("|---|---:|---|---:|---:|---:|---|\n")
        for row in rows:
            issues = row["errors"] or row["warnings"] or "-"
            f.write(
                f"| `{row['file']}` | {row['report_index']} | {row['scenario']} | "
                f"{row['status']} | {row['score']} | {row['evidence_len']} | {issues} |\n"
            )
        f.write("\n## 满分建议\n\n")
        f.write("- 每个场景至少保留 1 份 PASS 的 JSON 输出作为技术报告样例。\n")
        f.write("- `evidence_chain` 建议至少 2~3 条，覆盖 metric/event/stack 中的两类。\n")
        f.write("- `suspected_root_cause` 的措辞要贴近官方参考根因，例如 CPU 计算热点、I/O 队列拥堵、direct reclaim、futex/mutex 锁竞争、read/write 高频系统调用。\n")
        f.write("- I/O 场景尽量包含 P99、平均时延、吞吐、队列深度；锁竞争场景尽量包含 off-CPU 阻塞占比、阻塞栈、waker/wakee。\n")

    print(f"[validate] wrote {md_path} and {csv_path}")
    return 1 if any(row["status"] == "FAIL" for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
