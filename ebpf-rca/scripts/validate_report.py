#!/usr/bin/env python3
"""Strictly validate ebpf-rca JSON sessions and JSONL reports.

Accepted inputs are one DiagnosticSession, one AnomalyReport, an array of
AnomalyReport objects, or one AnomalyReport object per non-empty JSONL line.
Every decoded value is validated; malformed/noisy text is never skipped.
"""

from __future__ import annotations

import csv
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPORT_REQUIRED = {
    "anomaly_type",
    "root_cause_code",
    "related_object",
    "key_metrics",
    "time_window",
    "suspected_root_cause",
    "confidence",
    "evidence_chain",
    "suggestion",
}
REQUIRED = sorted(REPORT_REQUIRED)
REPORT_FIELDS = REPORT_REQUIRED
RELATED_FIELDS = {"pid", "tid", "comm", "device", "lock_address", "scope"}
EVIDENCE_FIELDS = {"type", "name", "value", "threshold", "desc", "func"}
TIME_FIELDS = {"start", "end", "elapsed_ms"}

SESSION_REQUIRED = {
    "schema_version",
    "started_at",
    "ended_at",
    "elapsed_ms",
    "environment",
    "configuration",
    "collectors",
    "partial",
    "reports",
}
ENVIRONMENT_FIELDS = {"hostname", "os", "architecture", "kernel_release", "btf"}
CONFIG_REQUIRED = {"scenario", "interval_ms", "sustain", "allow_partial", "thresholds"}
CONFIG_FIELDS = CONFIG_REQUIRED | {"target_pid"}
COLLECTOR_REQUIRED = {"name", "requested", "initialized", "state", "poll_count"}
COLLECTOR_FIELDS = COLLECTOR_REQUIRED | {
    "last_poll_at",
    "error",
    "health_error",
    "health",
}
HEALTH_REQUIRED = {"program_runtime_ns", "program_run_count", "map_memory_bytes"}
HEALTH_FIELDS = HEALTH_REQUIRED | {"counters"}
SCENARIOS = {"cpu", "io", "mem", "lock", "syscall"}
REQUIRED_THRESHOLDS = {
    "cpu_util",
    "io_p99_ms",
    "mem_available_floor_pct",
    "lock_offcpu_ratio",
    "syscall_calls_per_sec",
}
TERMINAL_COLLECTOR_STATES = {"stopped", "failed"}
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"
)
ROOT_CAUSE_CODES = {
    "cpu.compute_hotspot",
    "cpu.scheduler_pressure",
    "io.queue_congestion",
    "io.device_latency",
    "mem.reclaim_pressure",
    "mem.oom_victim",
    "lock.futex_contention",
    "lock.kernel_sync_wait",
    "syscall.high_frequency",
    "syscall.high_latency",
}
ROOT_CAUSE_KEYWORDS = {
    "cpu": ["CPU", "计算", "busy", "热点", "饱和", "调度"],
    "io": ["I/O", "IO", "队列", "P99", "时延", "延迟", "吞吐", "设备"],
    "mem": ["内存", "reclaim", "kswapd", "缺页", "OOM", "回收"],
    "lock": ["锁", "futex", "mutex", "off-CPU", "阻塞", "唤醒"],
    "syscall": ["syscall", "系统调用", "read", "write", "fsync", "poll"],
}
UINT32_MAX = 2**32 - 1
UINT64_MAX = 2**64 - 1
INT64_MAX = 2**63 - 1


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON number {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    return json.loads(
        text,
        parse_constant=_reject_constant,
        object_pairs_hook=_object_without_duplicates,
    )


def decode_json_values(text: str) -> list[Any]:
    """Decode one strict JSON value or strict one-object-per-line JSONL."""
    text = text.strip()
    if not text:
        raise ValueError("empty file")

    try:
        return [strict_json_loads(text)]
    except (json.JSONDecodeError, ValueError) as single_error:
        values: list[Any] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = strict_json_loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"invalid JSONL line {line_no}: {exc}") from single_error
            if not isinstance(value, dict):
                raise ValueError(f"JSONL line {line_no} is not an object")
            values.append(value)
        if not values:
            raise ValueError("no JSON value") from single_error
        return values


def load_json_strict(path: Path) -> list[Any]:
    return decode_json_values(path.read_text(encoding="utf-8", errors="strict"))


def _require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    return value


def _require_exact_fields(
    value: dict[str, Any], required: set[str], allowed: set[str], where: str
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise ValueError(f"{where} missing required fields: {','.join(missing)}")
    if unknown:
        raise ValueError(f"{where} has unknown fields: {','.join(unknown)}")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_number(value: Any, where: str, *, minimum: float | None = None) -> float:
    if not _is_number(value) or not math.isfinite(float(value)):
        raise ValueError(f"{where} must be a finite number")
    number = float(value)
    if minimum is not None and number < minimum:
        raise ValueError(f"{where} must be >= {minimum:g}")
    return number


def _nonnegative_int(
    value: Any, where: str, *, maximum: int | None = None
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{where} must be a non-negative integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{where} must be <= {maximum}")
    return value


def _positive_int(value: Any, where: str, *, maximum: int | None = None) -> int:
    number = _nonnegative_int(value, where, maximum=maximum)
    if number == 0:
        raise ValueError(f"{where} must be positive")
    return number


def _nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be a non-empty string")
    return value


def _date_time(value: Any, where: str) -> datetime:
    text = _nonempty_string(value, where)
    if RFC3339_RE.fullmatch(text) is None:
        raise ValueError(f"{where} must be RFC3339 date-time")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{where} must be RFC3339 date-time: {exc}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{where} must include a UTC offset")
    return parsed


def _validate_json_numbers(value: Any, where: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{where} contains a non-finite number")
    if isinstance(value, dict):
        for key, nested in value.items():
            _validate_json_numbers(nested, f"{where}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _validate_json_numbers(nested, f"{where}[{index}]")


def validate_anomaly_report(report: Any, where: str = "AnomalyReport") -> dict[str, Any]:
    report = _require_object(report, where)
    _require_exact_fields(report, REPORT_REQUIRED, REPORT_FIELDS, where)
    _nonempty_string(report["anomaly_type"], f"{where}.anomaly_type")
    code = _nonempty_string(report["root_cause_code"], f"{where}.root_cause_code")
    if code not in ROOT_CAUSE_CODES:
        raise ValueError(f"{where}.root_cause_code is invalid: {code!r}")

    related = _require_object(report["related_object"], f"{where}.related_object")
    _require_exact_fields(related, set(), RELATED_FIELDS, f"{where}.related_object")
    if not related:
        raise ValueError(f"{where}.related_object has no identifiable target")
    for field in ("pid", "tid"):
        if field in related:
            _positive_int(
                related[field],
                f"{where}.related_object.{field}",
                maximum=UINT32_MAX,
            )
    if "lock_address" in related:
        _positive_int(
            related["lock_address"],
            f"{where}.related_object.lock_address",
            maximum=UINT64_MAX,
        )
    for field in ("comm", "device"):
        if field in related:
            _nonempty_string(related[field], f"{where}.related_object.{field}")
    if "scope" in related and related["scope"] not in {"process", "target_tree", "system"}:
        raise ValueError(f"{where}.related_object.scope is invalid")
    if related.get("scope") == "system" and any(
        field in related for field in ("pid", "tid", "lock_address")
    ):
        raise ValueError(f"{where}.related_object system scope must not claim pid/tid/lock_address")
    if code.startswith("cpu.") and not {"pid", "tid"} <= related.keys():
        raise ValueError(f"{where}.related_object requires TGID pid and hottest tid for CPU")
    if code.startswith("io.") and "device" not in related:
        raise ValueError(f"{where}.related_object.device is required for I/O")
    if code == "lock.futex_contention" and not {"pid", "tid"} <= related.keys():
        raise ValueError(f"{where}.related_object requires pid and tid for futex contention")
    if code == "lock.futex_contention" and "lock_address" not in related:
        raise ValueError(f"{where}.related_object.lock_address is required for futex contention")
    if code == "lock.kernel_sync_wait" and not {"pid", "tid"} <= related.keys():
        raise ValueError(f"{where}.related_object requires pid and tid for kernel synchronization")
    if code.startswith("syscall.") and "pid" not in related:
        raise ValueError(f"{where}.related_object.pid is required for syscall")

    metrics = _require_object(report["key_metrics"], f"{where}.key_metrics")
    if not metrics:
        raise ValueError(f"{where}.key_metrics is empty")
    _validate_json_numbers(metrics, f"{where}.key_metrics")

    window = _require_object(report["time_window"], f"{where}.time_window")
    _require_exact_fields(window, TIME_FIELDS, TIME_FIELDS, f"{where}.time_window")
    start = _date_time(window["start"], f"{where}.time_window.start")
    end = _date_time(window["end"], f"{where}.time_window.end")
    if end <= start:
        raise ValueError(f"{where}.time_window.start must be before end")
    elapsed = _finite_number(window["elapsed_ms"], f"{where}.time_window.elapsed_ms")
    if elapsed <= 0:
        raise ValueError(f"{where}.time_window.elapsed_ms must be positive")
    expected_elapsed = (end - start).total_seconds() * 1000
    if abs(elapsed - expected_elapsed) > max(0.01, expected_elapsed * 0.001):
        raise ValueError(f"{where}.time_window.elapsed_ms does not match start/end")

    _nonempty_string(report["suspected_root_cause"], f"{where}.suspected_root_cause")
    confidence = _finite_number(report["confidence"], f"{where}.confidence")
    if not 0 <= confidence <= 1:
        raise ValueError(f"{where}.confidence must be in [0,1]")
    evidence = report["evidence_chain"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError(f"{where}.evidence_chain must be a non-empty array")
    for index, item in enumerate(evidence):
        item_where = f"{where}.evidence_chain[{index}]"
        item = _require_object(item, item_where)
        _require_exact_fields(item, {"type", "name"}, EVIDENCE_FIELDS, item_where)
        _nonempty_string(item["type"], f"{item_where}.type")
        _nonempty_string(item["name"], f"{item_where}.name")
        for field in ("desc", "func"):
            if field in item and not isinstance(item[field], str):
                raise ValueError(f"{item_where}.{field} must be a string")
        _validate_json_numbers(item, item_where)
    _nonempty_string(report["suggestion"], f"{where}.suggestion")
    return report


def _validate_health(value: Any, where: str) -> None:
    health = _require_object(value, where)
    _require_exact_fields(health, HEALTH_REQUIRED, HEALTH_FIELDS, where)
    for field in HEALTH_REQUIRED:
        _nonnegative_int(health[field], f"{where}.{field}", maximum=UINT64_MAX)
    if "counters" not in health:
        raise ValueError(f"{where}.counters is required")
    counters = _require_object(health["counters"], f"{where}.counters")
    for name, counter in counters.items():
        _nonnegative_int(counter, f"{where}.counters.{name}", maximum=UINT64_MAX)


def validate_diagnostic_session(session: Any, where: str = "DiagnosticSession") -> dict[str, Any]:
    session = _require_object(session, where)
    _require_exact_fields(session, SESSION_REQUIRED, SESSION_REQUIRED, where)
    if session["schema_version"] != "1.0":
        raise ValueError(f"{where}.schema_version must be '1.0'")
    started = _date_time(session["started_at"], f"{where}.started_at")
    ended = _date_time(session["ended_at"], f"{where}.ended_at")
    if ended < started:
        raise ValueError(f"{where}.ended_at precedes started_at")
    elapsed = _finite_number(session["elapsed_ms"], f"{where}.elapsed_ms", minimum=0)
    expected_elapsed = (ended - started).total_seconds() * 1000
    if abs(elapsed - expected_elapsed) > max(0.01, expected_elapsed * 0.001):
        raise ValueError(f"{where}.elapsed_ms does not match started_at/ended_at")

    environment = _require_object(session["environment"], f"{where}.environment")
    _require_exact_fields(environment, ENVIRONMENT_FIELDS, ENVIRONMENT_FIELDS, f"{where}.environment")
    for field in ("hostname", "os", "architecture", "kernel_release"):
        _nonempty_string(environment[field], f"{where}.environment.{field}")
    if not isinstance(environment["btf"], bool):
        raise ValueError(f"{where}.environment.btf must be boolean")

    config = _require_object(session["configuration"], f"{where}.configuration")
    _require_exact_fields(config, CONFIG_REQUIRED, CONFIG_FIELDS, f"{where}.configuration")
    scenario = config["scenario"]
    if scenario not in SCENARIOS | {"all"}:
        raise ValueError(f"{where}.configuration.scenario is invalid")
    _positive_int(
        config["interval_ms"],
        f"{where}.configuration.interval_ms",
        maximum=INT64_MAX,
    )
    _positive_int(
        config["sustain"], f"{where}.configuration.sustain", maximum=INT64_MAX
    )
    if "target_pid" in config:
        _positive_int(
            config["target_pid"],
            f"{where}.configuration.target_pid",
            maximum=UINT32_MAX,
        )
    if not isinstance(config["allow_partial"], bool):
        raise ValueError(f"{where}.configuration.allow_partial must be boolean")
    thresholds = _require_object(config["thresholds"], f"{where}.configuration.thresholds")
    missing_thresholds = sorted(REQUIRED_THRESHOLDS - thresholds.keys())
    if missing_thresholds:
        raise ValueError(f"{where}.configuration.thresholds missing: {','.join(missing_thresholds)}")
    if set(thresholds) != REQUIRED_THRESHOLDS:
        extra = sorted(set(thresholds) - REQUIRED_THRESHOLDS)
        raise ValueError(f"{where}.configuration.thresholds has unknown fields: {','.join(extra)}")
    for name, value in thresholds.items():
        _finite_number(value, f"{where}.configuration.thresholds.{name}", minimum=0)

    collectors = session["collectors"]
    if not isinstance(collectors, list) or not collectors:
        raise ValueError(f"{where}.collectors must be a non-empty array")
    expected_collectors = SCENARIOS if scenario == "all" else {scenario}
    seen: set[str] = set()
    failed = False
    for index, value in enumerate(collectors):
        item_where = f"{where}.collectors[{index}]"
        collector = _require_object(value, item_where)
        _require_exact_fields(collector, COLLECTOR_REQUIRED, COLLECTOR_FIELDS, item_where)
        name = collector["name"]
        if name not in expected_collectors:
            raise ValueError(f"{item_where}.name is not requested by scenario: {name!r}")
        if name in seen:
            raise ValueError(f"{where}.collectors contains duplicate {name!r}")
        seen.add(name)
        if collector["requested"] is not True:
            raise ValueError(f"{item_where}.requested must be true")
        if not isinstance(collector["initialized"], bool):
            raise ValueError(f"{item_where}.initialized must be boolean")
        state = collector["state"]
        if state not in TERMINAL_COLLECTOR_STATES:
            raise ValueError(f"{item_where}.state is non-terminal: {state!r}")
        poll_count = _nonnegative_int(
            collector["poll_count"], f"{item_where}.poll_count", maximum=UINT64_MAX
        )
        if state == "stopped" and not collector["initialized"]:
            raise ValueError(f"{item_where} stopped without initialization")
        if "error" in collector:
            _nonempty_string(collector["error"], f"{item_where}.error")
        if state == "failed":
            failed = True
            if "error" not in collector:
                raise ValueError(f"{item_where}.error is required for failed state")
        if "last_poll_at" in collector:
            _date_time(collector["last_poll_at"], f"{item_where}.last_poll_at")
        if "health_error" in collector:
            _nonempty_string(collector["health_error"], f"{item_where}.health_error")
        if "health" in collector:
            _validate_health(collector["health"], f"{item_where}.health")
        if state == "stopped" and (
            "error" in collector or "health_error" in collector or "health" not in collector
        ):
            raise ValueError(f"{item_where} stopped without a clean health snapshot")
    if seen != expected_collectors:
        missing = sorted(expected_collectors - seen)
        raise ValueError(f"{where}.collectors coverage mismatch; missing: {','.join(missing)}")
    if not isinstance(session["partial"], bool):
        raise ValueError(f"{where}.partial must be boolean")
    if session["partial"] != failed:
        raise ValueError(f"{where}.partial does not match collector failure state")

    reports = session["reports"]
    if not isinstance(reports, list):
        raise ValueError(f"{where}.reports must be an array, not null")
    for index, report in enumerate(reports):
        validated = validate_anomaly_report(report, f"{where}.reports[{index}]")
        if scenario != "all" and not validated["root_cause_code"].startswith(f"{scenario}."):
            raise ValueError(f"{where}.reports[{index}].root_cause_code does not match scenario")
    return session


def decode_diagnostic_session_json(
    text: str, where: str = "DiagnosticSession"
) -> dict[str, Any]:
    """Strictly decode exactly one DiagnosticSession and validate all semantics."""
    return validate_diagnostic_session(strict_json_loads(text), where)


def iter_validated_documents(values: list[Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return (kind, object) entries after validating every decoded document."""
    documents: list[tuple[str, dict[str, Any]]] = []
    for value_index, value in enumerate(values):
        candidates: list[Any]
        if isinstance(value, list):
            if not value:
                raise ValueError(f"top-level array {value_index} is empty")
            candidates = value
        else:
            candidates = [value]
        for document_index, candidate in enumerate(candidates):
            where = f"document[{value_index}][{document_index}]"
            candidate = _require_object(candidate, where)
            if "reports" in candidate or "schema_version" in candidate:
                documents.append(("session", validate_diagnostic_session(candidate, where)))
            else:
                documents.append(("report", validate_anomaly_report(candidate, where)))
    if not documents:
        raise ValueError("no JSON document found")
    return documents


def has_any_key(obj: Any, keys: list[str]) -> bool:
    return isinstance(obj, dict) and any(k in obj and obj[k] not in (None, "", []) for k in keys)


def numeric_metric_count(obj: Any) -> int:
    count = 0
    if isinstance(obj, dict):
        for value in obj.values():
            if _is_number(value) and math.isfinite(float(value)):
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
    code = str(report.get("root_cause_code", ""))
    if "." in code and code.split(".", 1)[0] in SCENARIOS:
        return code.split(".", 1)[0]
    for scenario in ("lock", "syscall", "mem", "io", "cpu"):
        if name.startswith(f"{scenario}_") or name.startswith(f"{scenario}-"):
            return scenario
    for scenario in ("lock", "syscall", "mem", "io", "cpu"):
        if scenario in text:
            return scenario
    return "unknown"


def check_one(path: Path, idx: int, report: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    warns: list[str] = []
    score = 100
    if numeric_metric_count(report["key_metrics"]) == 0:
        errors.append("key_metrics_no_numeric_metric")
        score -= 8
    scenario = infer_scenario(path, report)
    root_text = str(report["suspected_root_cause"]) + " " + str(report["anomaly_type"])
    if scenario in ROOT_CAUSE_KEYWORDS and not any(
        keyword.lower() in root_text.lower() for keyword in ROOT_CAUSE_KEYWORDS[scenario]
    ):
        warns.append("root_cause_wording_not_close_to_expected_scenario")
        score -= 5
    score = max(0, score)
    return {
        "file": str(path),
        "report_index": idx,
        "scenario": scenario,
        "score": score,
        "status": "PASS" if not errors and score >= 85 else ("WARN" if score >= 70 else "FAIL"),
        "missing_required": "",
        "errors": ";".join(errors),
        "warnings": ";".join(warns),
        "evidence_len": len(report["evidence_chain"]),
        "anomaly_type": str(report["anomaly_type"]),
        "root_cause": str(report["suspected_root_cause"]),
    }


def session_lifecycle_row(path: Path, session: dict[str, Any]) -> dict[str, Any]:
    failed = [
        str(item["name"])
        for item in session["collectors"]
        if item["state"] == "failed"
    ]
    clean = session["partial"] is False and not failed
    errors = "" if clean else (
        "collector_failure:partial session; failed=" + ",".join(failed)
    )
    return {
        "file": str(path),
        "report_index": 0,
        "scenario": str(session["configuration"]["scenario"]),
        "score": 100 if clean else 0,
        "status": "PASS" if clean else "FAIL",
        "missing_required": "",
        "errors": errors,
        "warnings": "",
        "evidence_len": 0,
        "anomaly_type": "",
        "root_cause": "",
    }


def failure_row(path: Path, exc: Exception) -> dict[str, Any]:
    return {
        "file": str(path),
        "report_index": 0,
        "scenario": "unknown",
        "score": 0,
        "status": "FAIL",
        "missing_required": "",
        "errors": f"validation_error:{exc}",
        "warnings": "",
        "evidence_len": 0,
        "anomaly_type": "",
        "root_cause": "",
    }


def validate_paths(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        try:
            documents = iter_validated_documents(load_json_strict(path))
            report_index = 0
            for kind, document in documents:
                if kind == "report":
                    report_index += 1
                    rows.append(check_one(path, report_index, document))
                    continue
                reports = document["reports"]
                clean_session = document["partial"] is False and all(
                    item["state"] == "stopped" for item in document["collectors"]
                )
                # A failed session is valid audit data, but never valid PASS
                # evidence. Emit a lifecycle row even when nested reports exist
                # so a partial run cannot hide behind individually valid reports.
                if not reports or not clean_session:
                    rows.append(session_lifecycle_row(path, document))
                for report in reports:
                    report_index += 1
                    rows.append(check_one(path, report_index, report))
        except Exception as exc:
            rows.append(failure_row(path, exc))
    return rows


def write_results(rows: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "schema_check.csv"
    md_path = out_dir / "schema_check.md"
    fields = [
        "file", "report_index", "scenario", "status", "score", "evidence_len",
        "missing_required", "errors", "warnings", "anomaly_type", "root_cause",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    by_scenario: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_scenario.setdefault(str(row["scenario"]), []).append(row)
    with md_path.open("w", encoding="utf-8") as stream:
        stream.write("# ebpf-rca 结构化输出校验报告\n\n")
        stream.write("每个输入文档均经过严格 JSON、会话生命周期与报告语义校验。\n\n")
        stream.write("## 汇总\n\n")
        stream.write("| 场景 | 记录数 | PASS | WARN | FAIL | 平均分 |\n")
        stream.write("|---|---:|---:|---:|---:|---:|\n")
        for scenario, items in sorted(by_scenario.items()):
            avg = sum(float(item["score"]) for item in items) / len(items)
            stream.write(
                f"| {scenario} | {len(items)} | "
                f"{sum(1 for item in items if item['status'] == 'PASS')} | "
                f"{sum(1 for item in items if item['status'] == 'WARN')} | "
                f"{sum(1 for item in items if item['status'] == 'FAIL')} | {avg:.1f} |\n"
            )
        stream.write("\n## 明细\n\n")
        stream.write("| 文件 | 序号 | 场景 | 状态 | 分数 | 证据条数 | 问题 |\n")
        stream.write("|---|---:|---|---:|---:|---:|---|\n")
        for row in rows:
            issues = row["errors"] or row["warnings"] or "-"
            stream.write(
                f"| `{row['file']}` | {row['report_index']} | {row['scenario']} | "
                f"{row['status']} | {row['score']} | {row['evidence_len']} | {issues} |\n"
            )
    print(f"[validate] wrote {md_path} and {csv_path}")


def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: python3 scripts/validate_report.py outputs/repro/*.json", file=sys.stderr)
        return 2
    rows = validate_paths([Path(raw) for raw in argv])
    write_results(rows, Path("outputs/validation"))
    return 1 if any(row["status"] == "FAIL" for row in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
