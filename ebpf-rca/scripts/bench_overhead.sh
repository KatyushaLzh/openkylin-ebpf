#!/usr/bin/env bash
# Strict paired overhead benchmark for ebpf-rca.
#
# Evidence model:
#   workload: stress-ng bogo ops or fio JSON IOPS/bandwidth/P99
#   userspace: ebpf-rca process CPU and RSS sampled from /proc
#   kernel:    DiagnosticSession collector health runtime/run-count/map memory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATOR_PY="$SCRIPT_DIR/validate_report.py"

SCENARIO="all"
DURATION_SEC=60
REPEAT=5
OUT_DIR="outputs/bench"
TOOL="./bin/ebpf-rca"
INTERVAL="1s"
WARMUP_SEC=3
MARGIN_SEC=5
COOLDOWN_SEC=2
SUDO="sudo"
STRESS_NG_BIN="${STRESS_NG:-}"
IO_SIZE="${IO_SIZE:-512M}"
MEM_BYTES="${MEM_BYTES:-50%}"
CPU_WORKERS="${CPU_WORKERS:-$(nproc)}"

usage() {
  cat <<'USAGE'
Usage: bash scripts/bench_overhead.sh [options]

Options:
  --scenario cpu|io|mem|lock|syscall|all  all runs five individual cases plus a combined all-mode case
  --duration SECONDS                      workload duration (default: 60)
  --repeat N                              paired rounds; must be >= 5 (default: 5)
  --out DIR                               artifact directory (default: outputs/bench)
  --tool PATH                             ebpf-rca binary (default: ./bin/ebpf-rca)
  --interval DURATION                     collector interval (default: 1s)
  --warmup SECONDS                        tool warmup before workload (default: 3)
  --margin SECONDS                        tool tail after workload (default: 5)
  --cooldown SECONDS                      delay between paired phases (default: 2)
  --no-sudo                               run tool without sudo
  -h, --help                              show this help

Odd rounds run baseline first; even rounds run with-tool first. Raw workload
logs, fio JSON, tool sessions and /proc samples are retained under OUT/.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario) SCENARIO="${2:-}"; shift 2 ;;
    --duration) DURATION_SEC="${2:-}"; shift 2 ;;
    --repeat) REPEAT="${2:-}"; shift 2 ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --tool) TOOL="${2:-}"; shift 2 ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --warmup) WARMUP_SEC="${2:-}"; shift 2 ;;
    --margin) MARGIN_SEC="${2:-}"; shift 2 ;;
    --cooldown) COOLDOWN_SEC="${2:-}"; shift 2 ;;
    --no-sudo) SUDO=""; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_uint() {
  local name="$1" value="$2" minimum="$3"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < minimum )); then
    echo "$name must be an integer >= $minimum, got $value" >&2
    exit 2
  fi
}

require_uint --duration "$DURATION_SEC" 1
require_uint --repeat "$REPEAT" 5
require_uint --warmup "$WARMUP_SEC" 0
require_uint --margin "$MARGIN_SEC" 1
require_uint --cooldown "$COOLDOWN_SEC" 0
require_uint CPU_WORKERS "$CPU_WORKERS" 1

case "$SCENARIO" in
  cpu|io|mem|lock|syscall|all) ;;
  *) echo "unknown scenario: $SCENARIO" >&2; exit 2 ;;
esac

if [[ ! -x "$TOOL" ]]; then
  echo "missing executable tool: $TOOL" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 2
fi
if [[ ! -r "$VALIDATOR_PY" ]]; then
  echo "missing strict DiagnosticSession validator: $VALIDATOR_PY" >&2
  exit 2
fi
if (( $(id -u) == 0 )); then
  SUDO=""
elif [[ -n "$SUDO" ]]; then
  if ! "$SUDO" -n true >/dev/null 2>&1; then
    echo "sudo cannot run non-interactively; run as root or pass --no-sudo with BPF capabilities" >&2
    exit 2
  fi
fi

find_stress_ng() {
  if [[ -n "$STRESS_NG_BIN" && -x "$STRESS_NG_BIN" ]]; then
    return 0
  fi
  local local_bin="../.build_deps/bin/stress-ng"
  if [[ -x "$local_bin" ]]; then
    STRESS_NG_BIN="$local_bin"
    return 0
  fi
  if command -v stress-ng >/dev/null 2>&1; then
    STRESS_NG_BIN="$(command -v stress-ng)"
    return 0
  fi
  return 1
}

CASES=()
if [[ "$SCENARIO" == "all" ]]; then
  CASES=(cpu io mem lock syscall all)
else
  CASES=("$SCENARIO")
fi

need_stress=0
need_fio=0
for case_name in "${CASES[@]}"; do
  [[ "$case_name" != "io" ]] && need_stress=1
  [[ "$case_name" == "io" || "$case_name" == "all" ]] && need_fio=1
done
if (( need_stress == 1 )) && ! find_stress_ng; then
  echo "stress-ng is required" >&2
  exit 2
fi
if (( need_fio == 1 )) && ! command -v fio >/dev/null 2>&1; then
  echo "fio is required" >&2
  exit 2
fi

RAW_DIR="$OUT_DIR/raw"
SESSION_DIR="$OUT_DIR/tool_sessions"
RESOURCE_DIR="$OUT_DIR/resource"
mkdir -p "$RAW_DIR" "$SESSION_DIR" "$RESOURCE_DIR"

RUNS_TSV="$OUT_DIR/bench_runs.tsv"
SUMMARY_CSV="$OUT_DIR/bench_summary.csv"
SUMMARY_JSON="$OUT_DIR/bench_summary.json"
SUMMARY_MD="$OUT_DIR/bench.md"
printf 'case\trepeat\torder\tphase\tworkload_status\ttool_status\telapsed_sec\tmetrics_json\tworkload_log\ttool_session\tresource_csv\ttool_log\n' >"$RUNS_TSV"

CLEANUP_PIDS=()
cleanup() {
  set +e
  local pid
  for pid in "${CLEANUP_PIDS[@]:-}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1
      wait "$pid" >/dev/null 2>&1
    fi
  done
  set -e
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

track_pid() {
  CLEANUP_PIDS+=("$1")
}

now_ns() {
  date +%s%N
}

elapsed_seconds() {
  python3 - "$1" "$2" <<'PY'
import sys
print(f"{(int(sys.argv[2]) - int(sys.argv[1])) / 1e9:.6f}")
PY
}

stress_args() {
  local case_name="$1"
  STRESS_ARGS=(--timeout "${DURATION_SEC}s" --metrics-brief)
  case "$case_name" in
    cpu)
      STRESS_ARGS+=(--cpu "$CPU_WORKERS" --cpu-method matrixprod)
      ;;
    mem)
      STRESS_ARGS+=(--vm 2 --vm-bytes "$MEM_BYTES" --vm-keep)
      ;;
    lock)
      STRESS_ARGS+=(--mutex 8)
      ;;
    syscall)
      STRESS_ARGS+=(--syscall 4)
      ;;
    all)
      STRESS_ARGS+=(--cpu "$CPU_WORKERS" --cpu-method matrixprod --vm 2 --vm-bytes "$MEM_BYTES" --vm-keep --mutex 8 --syscall 4)
      ;;
    *)
      return 2
      ;;
  esac
}

run_stress() {
  local case_name="$1" log="$2"
  stress_args "$case_name"
  "$STRESS_NG_BIN" "${STRESS_ARGS[@]}" >"$log" 2>&1
}

run_fio() {
  local io_file="$1" json_file="$2" stderr_file="$3"
  fio --name=rca-overhead --filename="$io_file" --size="$IO_SIZE" \
    --rw=randrw --rwmixread=70 --bs=4k --direct=1 --ioengine=libaio \
    --iodepth=64 --numjobs=4 --runtime="$DURATION_SEC" --time_based \
    --group_reporting --output-format=json --output="$json_file" \
    >"$stderr_file" 2>&1
}

parse_workload_metrics() {
  local case_name="$1" stress_log="$2" fio_json="$3" output_json="$4"
  python3 - "$case_name" "$stress_log" "$fio_json" "$output_json" <<'PY'
import json
import math
import re
import sys
from pathlib import Path

case_name, stress_path, fio_path, out_path = sys.argv[1:]
out = {"case": case_name}

if case_name != "io":
    text = Path(stress_path).read_text(encoding="utf-8", errors="strict")
    per_stressor = {}
    pattern = re.compile(
        r"stress-ng:\s+metrc:\s+\[[0-9]+\]\s+([A-Za-z0-9_-]+)\s+"
        r"([0-9]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)"
    )
    for match in pattern.finditer(text):
        name = match.group(1)
        per_stressor[name] = {
            "bogo_ops": int(match.group(2)),
            "real_time_sec": float(match.group(3)),
            "user_time_sec": float(match.group(4)),
            "system_time_sec": float(match.group(5)),
            "bogo_ops_per_sec": float(match.group(6)),
        }
    if not per_stressor:
        raise SystemExit("stress-ng log contains no metrics rows")
    if any(v["bogo_ops"] <= 0 or v["bogo_ops_per_sec"] <= 0 for v in per_stressor.values()):
        raise SystemExit("stress-ng returned non-positive bogo metrics")
    out["stress_ng"] = {
        "bogo_ops": sum(v["bogo_ops"] for v in per_stressor.values()),
        "bogo_ops_per_sec": sum(v["bogo_ops_per_sec"] for v in per_stressor.values()),
        "per_stressor": per_stressor,
    }

if case_name in ("io", "all"):
    fio = json.loads(Path(fio_path).read_text(encoding="utf-8", errors="strict"))
    jobs = fio.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise SystemExit("fio JSON has no jobs")
    iops = 0.0
    bandwidth = 0.0
    p99_values = []
    for job in jobs:
        for direction in ("read", "write"):
            metrics = job.get(direction, {})
            iops += float(metrics.get("iops") or 0)
            bw = metrics.get("bw_bytes")
            if bw is None:
                bw = float(metrics.get("bw") or 0) * 1024.0
            bandwidth += float(bw)
            for key, scale in (("clat_ns", 1.0), ("lat_ns", 1.0), ("clat_us", 1000.0), ("lat_us", 1000.0)):
                lat = metrics.get(key)
                if not isinstance(lat, dict):
                    continue
                percentiles = lat.get("percentile")
                if not isinstance(percentiles, dict) or not percentiles:
                    continue
                choices = []
                for percentile, value in percentiles.items():
                    try:
                        choices.append((abs(float(percentile) - 99.0), float(value) * scale))
                    except (TypeError, ValueError):
                        continue
                if choices:
                    p99_values.append(min(choices)[1])
                    break
    p99_ns = max(p99_values, default=0.0)
    if not all(math.isfinite(v) and v > 0 for v in (iops, bandwidth, p99_ns)):
        raise SystemExit(f"invalid fio metrics: iops={iops} bandwidth={bandwidth} p99_ns={p99_ns}")
    out["fio"] = {
        "iops": iops,
        "bandwidth_bytes_per_sec": bandwidth,
        "p99_latency_ns": p99_ns,
    }

Path(out_path).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

run_workload() {
  local case_name="$1" prefix="$2" io_file="$3"
  local workload_log="${prefix}_workload.log"
  local stress_log="${prefix}_stress.log"
  local fio_json="${prefix}_fio.json"
  local fio_stderr="${prefix}_fio.stderr"
  local metrics_json="${prefix}_metrics.json"
  local workload_status=0

  : >"$workload_log"
  if [[ "$case_name" == "io" ]]; then
    run_fio "$io_file" "$fio_json" "$fio_stderr"
    workload_status=$?
  elif [[ "$case_name" == "all" ]]; then
    run_stress "$case_name" "$stress_log" &
    local stress_pid=$!
    track_pid "$stress_pid"
    run_fio "$io_file" "$fio_json" "$fio_stderr"
    local fio_status=$?
    wait "$stress_pid"
    local stress_status=$?
    if (( fio_status != 0 )); then
      workload_status=$fio_status
    else
      workload_status=$stress_status
    fi
  else
    run_stress "$case_name" "$stress_log"
    workload_status=$?
  fi

  {
    printf 'case=%s\n' "$case_name"
    printf 'status=%s\n' "$workload_status"
    printf 'stress_log=%s\n' "$stress_log"
    printf 'fio_json=%s\n' "$fio_json"
    printf 'fio_stderr=%s\n' "$fio_stderr"
  } >>"$workload_log"

  if (( workload_status == 0 )); then
    parse_workload_metrics "$case_name" "$stress_log" "$fio_json" "$metrics_json"
    local metric_status=$?
    if (( metric_status != 0 )); then
      workload_status=$metric_status
    fi
  fi
  WORKLOAD_STATUS=$workload_status
  WORKLOAD_LOG="$workload_log"
  WORKLOAD_METRICS="$metrics_json"
  return "$workload_status"
}

prepare_io_file() {
  local path="$1"
  rm -f "$path"
  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "$IO_SIZE" "$path"
  else
    truncate -s "$IO_SIZE" "$path"
  fi
}

tool_args() {
  local case_name="$1" session_path="$2"
  TOOL_ARGS=(
    "$TOOL"
    --scenario "$case_name"
    --interval "$INTERVAL"
    --duration "$((DURATION_SEC + WARMUP_SEC + MARGIN_SEC))s"
    --format json
    --output "$session_path"
  )
}

start_tool() {
  local log="$1"
  if [[ -n "$SUDO" ]]; then
    "$SUDO" -n "${TOOL_ARGS[@]}" >"$log" 2>&1 &
  else
    "${TOOL_ARGS[@]}" >"$log" 2>&1 &
  fi
  TOOL_PID=$!
  track_pid "$TOOL_PID"
}

resolve_monitor_pid() {
  local pid="$1" child_file child
  child_file="/proc/$pid/task/$pid/children"
  for _ in $(seq 1 30); do
    if [[ -r "$child_file" ]]; then
      child=""
      read -r child _ <"$child_file" || :
      if [[ -n "$child" && -r "/proc/$child/stat" ]]; then
        printf '%s\n' "$child"
        return
      fi
    fi
    if [[ -r "/proc/$pid/stat" ]]; then
      sleep 0.1
    else
      break
    fi
  done
  printf '%s\n' "$pid"
}

monitor_process() {
  local pid="$1" csv_path="$2"
  python3 - "$pid" "$csv_path" <<'PY'
import csv
import sys
import time
from pathlib import Path

pid, output = int(sys.argv[1]), Path(sys.argv[2])
proc = Path("/proc") / str(pid)
with output.open("w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["time_ns", "utime_ticks", "stime_ticks", "rss_kb", "hwm_kb"])
    while True:
        try:
            stat = (proc / "stat").read_text(encoding="ascii")
            fields = stat[stat.rfind(")") + 2 :].split()
            utime, stime = int(fields[11]), int(fields[12])
            status = (proc / "status").read_text(encoding="ascii")
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
            break
        values = {}
        for line in status.splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, raw, *_ = line.split()
                values[key.rstrip(":")] = int(raw)
        writer.writerow([time.time_ns(), utime, stime, values.get("VmRSS", 0), values.get("VmHWM", 0)])
        f.flush()
        time.sleep(0.25)
PY
}

wait_for_tool() {
  local pid="$1" limit="$2"
  local elapsed=0 stat_text rest state
  while kill -0 "$pid" >/dev/null 2>&1; do
    if [[ -r "/proc/$pid/stat" ]]; then
      stat_text="$(<"/proc/$pid/stat")"
      rest="${stat_text##*) }"
      state="${rest%% *}"
      if [[ "$state" == "Z" ]]; then
        break
      fi
    fi
    if (( elapsed >= limit )); then
      kill "$pid" >/dev/null 2>&1
      sleep 1
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1
      fi
      wait "$pid" >/dev/null 2>&1
      return 124
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  wait "$pid"
}

append_run() {
  local case_name="$1" repeat_idx="$2" order="$3" phase="$4"
  local workload_status="$5" tool_status="$6" elapsed="$7" metrics="$8"
  local workload_log="$9" session_path="${10}" resource_csv="${11}" tool_log="${12}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$case_name" "$repeat_idx" "$order" "$phase" "$workload_status" "$tool_status" \
    "$elapsed" "$metrics" "$workload_log" "$session_path" "$resource_csv" "$tool_log" >>"$RUNS_TSV"
}

run_phase() {
  local case_name="$1" repeat_idx="$2" order="$3" phase="$4" io_file="$5"
  local stem="${case_name}_r${repeat_idx}_${phase}"
  local prefix="$RAW_DIR/$stem"
  local session_path="" resource_csv="" tool_log="" tool_status="NA"
  local monitor_pid="" monitor_target=""

  if [[ "$phase" == "with_tool" ]]; then
    session_path="$SESSION_DIR/${stem}_session.json"
    resource_csv="$RESOURCE_DIR/${stem}_process.csv"
    tool_log="$RAW_DIR/${stem}_tool.log"
    rm -f "$session_path" "$resource_csv" "$tool_log"
    tool_args "$case_name" "$session_path"
    start_tool "$tool_log"
    sleep "$WARMUP_SEC"
    if ! kill -0 "$TOOL_PID" >/dev/null 2>&1; then
      set +e
      wait "$TOOL_PID"
      tool_status=$?
      set -e
      append_run "$case_name" "$repeat_idx" "$order" "$phase" 125 "$tool_status" 0 \
        "${prefix}_metrics.json" "${prefix}_workload.log" "$session_path" "$resource_csv" "$tool_log"
      return
    fi
    if [[ -n "$SUDO" ]]; then
      monitor_target="$(resolve_monitor_pid "$TOOL_PID")"
    else
      monitor_target="$TOOL_PID"
    fi
    monitor_process "$monitor_target" "$resource_csv" &
    monitor_pid=$!
    track_pid "$monitor_pid"
  fi

  local start_ns end_ns workload_status elapsed
  start_ns="$(now_ns)"
  set +e
  run_workload "$case_name" "$prefix" "$io_file"
  workload_status=$?
  set -e
  end_ns="$(now_ns)"
  elapsed="$(elapsed_seconds "$start_ns" "$end_ns")"

  if [[ -n "$monitor_pid" ]]; then
    set +e
    kill "$monitor_pid" >/dev/null 2>&1
    wait "$monitor_pid" >/dev/null 2>&1
    set -e
  fi

  if [[ "$phase" == "with_tool" ]]; then
    set +e
    wait_for_tool "$TOOL_PID" "$((MARGIN_SEC + 10))"
    tool_status=$?
    set -e
  fi
  append_run "$case_name" "$repeat_idx" "$order" "$phase" "$workload_status" "$tool_status" "$elapsed" \
    "$WORKLOAD_METRICS" "$WORKLOAD_LOG" "$session_path" "$resource_csv" "$tool_log"
}

echo "[bench] cases=${CASES[*]} duration=${DURATION_SEC}s repeat=$REPEAT"
for case_name in "${CASES[@]}"; do
  for repeat_idx in $(seq 1 "$REPEAT"); do
    io_file="$RAW_DIR/${case_name}_r${repeat_idx}_fio.img"
    if [[ "$case_name" == "io" || "$case_name" == "all" ]]; then
      prepare_io_file "$io_file"
    fi
    if (( repeat_idx % 2 == 1 )); then
      order="baseline_first"
      phases=(baseline with_tool)
    else
      order="with_tool_first"
      phases=(with_tool baseline)
    fi
    for phase in "${phases[@]}"; do
      echo "[bench] case=$case_name repeat=$repeat_idx order=$order phase=$phase"
      run_phase "$case_name" "$repeat_idx" "$order" "$phase" "$io_file"
      sleep "$COOLDOWN_SEC"
    done
    rm -f "$io_file"
  done
done

set +e
python3 - "$RUNS_TSV" "$SUMMARY_CSV" "$SUMMARY_JSON" "$SUMMARY_MD" "$REPEAT" "$VALIDATOR_PY" <<'PY'
import csv
import datetime as dt
import importlib.util
import json
import math
import os
import platform
import statistics
import sys
from pathlib import Path

runs_path, csv_path, json_path, md_path, expected_repeat_raw, validator_path = sys.argv[1:]
expected_repeat = int(expected_repeat_raw)
errors = []

validator_spec = importlib.util.spec_from_file_location(
    "ebpf_rca_validate_report", validator_path
)
if validator_spec is None or validator_spec.loader is None:
    raise SystemExit(f"cannot load strict DiagnosticSession validator: {validator_path}")
report_validator = importlib.util.module_from_spec(validator_spec)
validator_spec.loader.exec_module(report_validator)

with open(runs_path, newline="", encoding="utf-8") as f:
    runs = list(csv.DictReader(f, delimiter="\t"))


def finite_number(value, label, *, positive=False):
    try:
        number = float(value)
    except (TypeError, ValueError):
        errors.append(f"{label}: missing/non-numeric value {value!r}")
        return None
    if not math.isfinite(number) or (positive and number <= 0):
        errors.append(f"{label}: invalid value {number}")
        return None
    return number


def load_metrics(row):
    path = Path(row["metrics_json"])
    try:
        value = report_validator.strict_json_loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as exc:
        errors.append(f"{row['case']} r{row['repeat']} {row['phase']}: invalid workload metrics {path}: {exc}")
        return {}
    if not isinstance(value, dict) or value.get("case") != row["case"]:
        errors.append(f"{path}: wrong workload metric envelope")
        return {}
    return value


def process_stats(path, label):
    try:
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except Exception as exc:
        errors.append(f"{label}: cannot read process samples: {exc}")
        return {}
    if len(rows) < 2:
        errors.append(f"{label}: need at least two process samples, got {len(rows)}")
        return {}
    try:
        first, last = rows[0], rows[-1]
        wall_sec = (int(last["time_ns"]) - int(first["time_ns"])) / 1e9
        ticks = (int(last["utime_ticks"]) + int(last["stime_ticks"])) - (
            int(first["utime_ticks"]) + int(first["stime_ticks"])
        )
        cpu_percent = ticks / os.sysconf("SC_CLK_TCK") / wall_sec * 100.0
        rss = [float(row["rss_kb"]) for row in rows]
        hwm = [float(row["hwm_kb"]) for row in rows]
    except Exception as exc:
        errors.append(f"{label}: invalid process sample: {exc}")
        return {}
    if wall_sec <= 0 or cpu_percent < 0 or max(rss + hwm) <= 0:
        errors.append(f"{label}: non-positive process metrics")
        return {}
    return {
        "sample_count": len(rows),
        "process_cpu_percent": cpu_percent,
        "process_avg_rss_mb": statistics.mean(rss) / 1024.0,
        "process_max_rss_mb": max(max(rss), max(hwm)) / 1024.0,
    }


def session_stats(path, expected_case, label, workload_elapsed_sec):
    try:
        session = report_validator.decode_diagnostic_session_json(
            Path(path).read_text(encoding="utf-8", errors="strict"), label
        )
    except Exception as exc:
        errors.append(f"{label}: invalid DiagnosticSession: {exc}")
        return {}
    if session.get("partial") is not False:
        errors.append(f"{label}: partial DiagnosticSession is not valid benchmark evidence")
    config = session.get("configuration")
    if not isinstance(config, dict) or config.get("scenario") != expected_case:
        errors.append(f"{label}: session scenario mismatch")
    collectors = session.get("collectors")
    expected_collectors = 5 if expected_case == "all" else 1
    if not isinstance(collectors, list) or len(collectors) != expected_collectors:
        errors.append(f"{label}: expected {expected_collectors} collector health records")
        return {}
    runtime_ns = 0
    run_count = 0
    map_bytes = 0
    required_counters = {
        "cpu": {"map_update_fail", "stack_capture_fail", "program_stats_unavailable", "map_memory_estimated"},
        "io": {"duplicate_issue", "completion_miss", "map_update_fail", "partial_completion", "io_error",
               "current_inflight", "average_queue_depth_milli", "program_stats_unavailable", "map_memory_estimated"},
        "mem": {"reclaim_start_update_fail", "reclaim_end_miss", "map_update_fail", "oom_update_fail",
                "target_update_fail", "map_memory_estimated"},
        "lock": {"futex_update_fail", "offcpu_update_fail", "map_update_fail", "stack_capture_fail",
                 "target_update_fail", "map_memory_estimated"},
        "syscall": {"start_update_fail", "exit_miss", "map_update_fail", "target_update_fail", "map_memory_estimated"},
    }
    for collector in collectors:
        if not isinstance(collector, dict) or collector.get("state") != "stopped" or not collector.get("initialized"):
            errors.append(f"{label}: collector lifecycle is not clean: {collector}")
            continue
        if collector.get("health_error"):
            errors.append(f"{label}: collector health error: {collector['health_error']}")
        health = collector.get("health")
        if not isinstance(health, dict):
            errors.append(f"{label}: collector {collector.get('name')} has no health snapshot")
            continue
        counters = health.get("counters")
        collector_name = collector.get("name")
        if isinstance(counters, dict) and collector_name in required_counters:
            missing = sorted(required_counters[collector_name] - counters.keys())
            if missing:
                errors.append(f"{label}: collector {collector_name} missing health counters: {','.join(missing)}")
        if not isinstance(counters, dict) or "map_memory_estimated" not in counters:
            errors.append(
                f"{label}: collector {collector.get('name')} does not declare whether map memory is exact"
            )
        else:
            estimated = counters.get("map_memory_estimated")
            if isinstance(estimated, bool) or not isinstance(estimated, (int, float)) or not math.isfinite(estimated):
                errors.append(
                    f"{label}: collector {collector.get('name')} has invalid map_memory_estimated={estimated!r}"
                )
            elif estimated != 0:
                errors.append(
                    f"{label}: collector {collector.get('name')} used estimated map memory; exact fdinfo memlock is required"
                )
        if isinstance(counters, dict):
            for counter_name, counter_value in counters.items():
                if isinstance(counter_value, bool) or not isinstance(counter_value, (int, float)):
                    errors.append(
                        f"{label}: collector {collector.get('name')} counter {counter_name} is invalid"
                    )
                    continue
                fatal_counter = counter_name.endswith("update_fail") or counter_name.endswith("_miss") or counter_name in {
                    "program_stats_unavailable",
                    "current_inflight",
                    "io_error",
                }
                if fatal_counter and counter_value != 0:
                    errors.append(
                        f"{label}: collector {collector.get('name')} counter {counter_name}={counter_value}, want 0"
                    )
        values = []
        for key in ("program_runtime_ns", "program_run_count", "map_memory_bytes"):
            value = finite_number(health.get(key), f"{label} {collector.get('name')} {key}")
            values.append(0 if value is None else int(value))
        runtime_ns += values[0]
        run_count += values[1]
        map_bytes += values[2]
    elapsed_ms = finite_number(session.get("elapsed_ms"), f"{label} session elapsed_ms", positive=True)
    if run_count <= 0:
        errors.append(f"{label}: summed BPF run_count must be positive")
    if runtime_ns <= 0:
        errors.append(f"{label}: summed BPF runtime must be positive")
    if map_bytes <= 0:
        errors.append(f"{label}: summed BPF map memory must be positive")
    # ProgramInfo runtime covers warmup + workload + drain. Charge all of it to
    # the workload interval instead of diluting it over the idle tail.
    workload_elapsed = finite_number(
        workload_elapsed_sec, f"{label} workload elapsed_sec", positive=True
    )
    bpf_cpu_percent = (
        None
        if workload_elapsed is None
        else runtime_ns / (workload_elapsed * 1e9) * 100.0
    )
    return {
        "bpf_runtime_ns": runtime_ns,
        "bpf_run_count": run_count,
        "bpf_map_memory_mb": map_bytes / 1024.0 / 1024.0,
        "bpf_cpu_percent": bpf_cpu_percent,
        "session_elapsed_ms": elapsed_ms,
    }


def pct_degradation(base, tool):
    if base is None or tool is None or base <= 0:
        return None
    return (base - tool) / base * 100.0


def pct_increase(base, tool):
    if base is None or tool is None or base <= 0:
        return None
    return (tool - base) / base * 100.0


by_pair = {}
for row in runs:
    key = (row["case"], int(row["repeat"]))
    by_pair.setdefault(key, {})[row["phase"]] = row

pair_rows = []
for case_name in sorted({key[0] for key in by_pair}):
    case_pairs = [key for key in by_pair if key[0] == case_name]
    if len(case_pairs) != expected_repeat:
        errors.append(f"{case_name}: expected {expected_repeat} pairs, got {len(case_pairs)}")
    for _, repeat_idx in sorted(case_pairs):
        pair = by_pair[(case_name, repeat_idx)]
        if set(pair) != {"baseline", "with_tool"}:
            errors.append(f"{case_name} r{repeat_idx}: incomplete pair {sorted(pair)}")
            continue
        baseline, tool = pair["baseline"], pair["with_tool"]
        for row in (baseline, tool):
            if row["workload_status"] != "0":
                errors.append(f"{case_name} r{repeat_idx} {row['phase']}: workload status {row['workload_status']}")
        if tool["tool_status"] != "0":
            errors.append(f"{case_name} r{repeat_idx}: tool status {tool['tool_status']}")
        base_metrics = load_metrics(baseline)
        tool_metrics = load_metrics(tool)
        proc = process_stats(tool["resource_csv"], f"{case_name} r{repeat_idx}")
        health = session_stats(
            tool["tool_session"], case_name, f"{case_name} r{repeat_idx}", tool["elapsed_sec"]
        )

        base_stress = base_metrics.get("stress_ng", {})
        tool_stress = tool_metrics.get("stress_ng", {})
        base_fio = base_metrics.get("fio", {})
        tool_fio = tool_metrics.get("fio", {})
        base_bogo = finite_number(base_stress.get("bogo_ops_per_sec"), f"{case_name} r{repeat_idx} baseline bogo rate", positive=True) if case_name != "io" else None
        tool_bogo = finite_number(tool_stress.get("bogo_ops_per_sec"), f"{case_name} r{repeat_idx} tool bogo rate", positive=True) if case_name != "io" else None
        base_bogo_ops = finite_number(base_stress.get("bogo_ops"), f"{case_name} r{repeat_idx} baseline bogo ops", positive=True) if case_name != "io" else None
        tool_bogo_ops = finite_number(tool_stress.get("bogo_ops"), f"{case_name} r{repeat_idx} tool bogo ops", positive=True) if case_name != "io" else None
        if case_name in ("io", "all"):
            base_iops = finite_number(base_fio.get("iops"), f"{case_name} r{repeat_idx} baseline IOPS", positive=True)
            tool_iops = finite_number(tool_fio.get("iops"), f"{case_name} r{repeat_idx} tool IOPS", positive=True)
            base_bw = finite_number(base_fio.get("bandwidth_bytes_per_sec"), f"{case_name} r{repeat_idx} baseline bandwidth", positive=True)
            tool_bw = finite_number(tool_fio.get("bandwidth_bytes_per_sec"), f"{case_name} r{repeat_idx} tool bandwidth", positive=True)
            base_p99 = finite_number(base_fio.get("p99_latency_ns"), f"{case_name} r{repeat_idx} baseline P99", positive=True)
            tool_p99 = finite_number(tool_fio.get("p99_latency_ns"), f"{case_name} r{repeat_idx} tool P99", positive=True)
        else:
            base_iops = tool_iops = base_bw = tool_bw = base_p99 = tool_p99 = None

        process_cpu = proc.get("process_cpu_percent")
        bpf_cpu = health.get("bpf_cpu_percent")
        combined_cpu = None if process_cpu is None or bpf_cpu is None else process_cpu + bpf_cpu
        process_mem = proc.get("process_max_rss_mb")
        map_mem = health.get("bpf_map_memory_mb")
        combined_mem = None if process_mem is None or map_mem is None else process_mem + map_mem
        pair_rows.append({
            "case": case_name,
            "repeat": repeat_idx,
            "order": baseline["order"],
            "baseline_elapsed_sec": finite_number(baseline["elapsed_sec"], f"{case_name} r{repeat_idx} baseline elapsed", positive=True),
            "with_tool_elapsed_sec": finite_number(tool["elapsed_sec"], f"{case_name} r{repeat_idx} tool elapsed", positive=True),
            "baseline_bogo_ops": base_bogo_ops,
            "with_tool_bogo_ops": tool_bogo_ops,
            "baseline_bogo_ops_per_sec": base_bogo,
            "with_tool_bogo_ops_per_sec": tool_bogo,
            "bogo_throughput_degradation_percent": pct_degradation(base_bogo, tool_bogo),
            "baseline_iops": base_iops,
            "with_tool_iops": tool_iops,
            "iops_degradation_percent": pct_degradation(base_iops, tool_iops),
            "baseline_bandwidth_bytes_per_sec": base_bw,
            "with_tool_bandwidth_bytes_per_sec": tool_bw,
            "bandwidth_degradation_percent": pct_degradation(base_bw, tool_bw),
            "baseline_p99_latency_ns": base_p99,
            "with_tool_p99_latency_ns": tool_p99,
            "p99_increase_percent": pct_increase(base_p99, tool_p99),
            **proc,
            **health,
            "combined_cpu_percent": combined_cpu,
            "combined_memory_mb": combined_mem,
        })

fields = [
    "case", "repeat", "order", "baseline_elapsed_sec", "with_tool_elapsed_sec",
    "baseline_bogo_ops", "with_tool_bogo_ops", "baseline_bogo_ops_per_sec", "with_tool_bogo_ops_per_sec",
    "bogo_throughput_degradation_percent", "baseline_iops", "with_tool_iops", "iops_degradation_percent",
    "baseline_bandwidth_bytes_per_sec", "with_tool_bandwidth_bytes_per_sec", "bandwidth_degradation_percent",
    "baseline_p99_latency_ns", "with_tool_p99_latency_ns", "p99_increase_percent",
    "sample_count", "process_cpu_percent", "bpf_cpu_percent", "combined_cpu_percent",
    "process_avg_rss_mb", "process_max_rss_mb", "bpf_map_memory_mb", "combined_memory_mb",
    "bpf_runtime_ns", "bpf_run_count", "session_elapsed_ms",
]
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows({key: row.get(key) for key in fields} for row in pair_rows)


def mean_metric(items, key):
    values = [item[key] for item in items if item.get(key) is not None]
    return statistics.mean(values) if values else None


def max_metric(items, key):
    values = [item[key] for item in items if item.get(key) is not None]
    return max(values) if values else None


summary = []
target_failures = []
for case_name in sorted({row["case"] for row in pair_rows}):
    items = [row for row in pair_rows if row["case"] == case_name]
    throughput_candidates = [
        mean_metric(items, "bogo_throughput_degradation_percent"),
        mean_metric(items, "iops_degradation_percent"),
        mean_metric(items, "bandwidth_degradation_percent"),
    ]
    throughput_candidates = [x for x in throughput_candidates if x is not None]
    max_throughput_degradation = max(throughput_candidates, default=None)
    p99_increase = mean_metric(items, "p99_increase_percent")
    max_memory = max_metric(items, "combined_memory_mb")
    case_target_failures = []
    if max_throughput_degradation is None:
        case_target_failures.append("missing throughput degradation")
    elif max_throughput_degradation > 5.0:
        case_target_failures.append(
            f"throughput degradation {max_throughput_degradation:.3f}% exceeds 5%"
        )
    if case_name in ("io", "all"):
        if p99_increase is None:
            case_target_failures.append("missing fio P99 increase")
        elif p99_increase > 5.0:
            case_target_failures.append(f"fio P99 increase {p99_increase:.3f}% exceeds 5%")
    if case_name == "all":
        if max_memory is None:
            case_target_failures.append("missing all-mode combined memory")
        elif max_memory > 64.0:
            case_target_failures.append(f"all-mode combined memory {max_memory:.3f} MiB exceeds 64 MiB")
    if case_target_failures:
        target_failures.extend(f"{case_name}: {failure}" for failure in case_target_failures)
    summary.append({
        "case": case_name,
        "pairs": len(items),
        "bogo_throughput_degradation_percent": mean_metric(items, "bogo_throughput_degradation_percent"),
        "iops_degradation_percent": mean_metric(items, "iops_degradation_percent"),
        "bandwidth_degradation_percent": mean_metric(items, "bandwidth_degradation_percent"),
        "p99_increase_percent": p99_increase,
        "process_cpu_percent": mean_metric(items, "process_cpu_percent"),
        "bpf_cpu_percent": mean_metric(items, "bpf_cpu_percent"),
        "combined_cpu_percent": mean_metric(items, "combined_cpu_percent"),
        "max_combined_memory_mb": max_memory,
        "bpf_runtime_ns": mean_metric(items, "bpf_runtime_ns"),
        "bpf_run_count": mean_metric(items, "bpf_run_count"),
        "performance_target_pass": not case_target_failures,
        "performance_target_failures": case_target_failures,
    })

generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
report = {
    "generated_at": generated,
    "kernel": platform.release(),
    "architecture": platform.machine(),
    "valid": not errors,
    "errors": errors,
    "acceptance_pass": not errors and not target_failures,
    "target_failures": target_failures,
    "method": {
        "paired_rounds": expected_repeat,
        "alternating_order": True,
        "throughput_target_max_degradation_percent": 5.0,
        "p99_target_max_increase_percent": 5.0,
        "all_mode_memory_target_mb": 64.0,
    },
    "summary": summary,
    "runs_tsv": runs_path,
    "paired_csv": csv_path,
}
Path(json_path).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def fmt(value, suffix=""):
    return "NA" if value is None else f"{value:.3f}{suffix}"


with open(md_path, "w", encoding="utf-8") as f:
    f.write("# ebpf-rca 严格性能开销基准\n\n")
    f.write(f"- 生成时间：{generated}\n- Kernel：{platform.release()}\n- 架构：{platform.machine()}\n")
    f.write(f"- 每场景配对轮数：{expected_repeat}（奇偶轮交换 baseline/with-tool 顺序）\n")
    f.write(f"- 数据完整性：{'PASS' if not errors else 'FAIL'}\n\n")
    f.write(f"- 性能验收：{'PASS' if not errors and not target_failures else 'FAIL'}\n\n")
    f.write("## 方法与口径\n\n")
    f.write("- stress-ng 场景比较两侧实际 bogo ops/s；I/O 比较 fio JSON 中 IOPS、带宽和读写方向较大的 P99。\n")
    f.write("- CPU 开销 = 工具进程 /proc CPU + 所有 BPF ProgramInfo runtime；同时保留 BPF run count。\n")
    f.write("- 内存开销 = 工具进程峰值 RSS + 所有 BPF map memory；all-mode 目标为不超过 64 MiB。\n")
    f.write("- 吞吐下降与 P99 增幅目标均不超过 5%。负下降表示 with-tool 吞吐更高，不截断数据。\n\n")
    f.write("## 汇总\n\n")
    f.write("| case | pairs | bogo下降 | IOPS下降 | 带宽下降 | P99增幅 | 进程CPU | BPF CPU | 合计CPU | 峰值合计内存 | 目标 |\n")
    f.write("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|\n")
    for item in summary:
        f.write(
            f"| {item['case']} | {item['pairs']} | {fmt(item['bogo_throughput_degradation_percent'], '%')} | "
            f"{fmt(item['iops_degradation_percent'], '%')} | {fmt(item['bandwidth_degradation_percent'], '%')} | "
            f"{fmt(item['p99_increase_percent'], '%')} | {fmt(item['process_cpu_percent'], '%')} | "
            f"{fmt(item['bpf_cpu_percent'], '%')} | {fmt(item['combined_cpu_percent'], '%')} | "
            f"{fmt(item['max_combined_memory_mb'], ' MiB')} | {'PASS' if item['performance_target_pass'] else 'FAIL'} |\n"
        )
    if errors:
        f.write("\n## 数据错误\n\n")
        for error in errors:
            f.write(f"- {error}\n")
    if target_failures:
        f.write("\n## 验收目标失败\n\n")
        for failure in target_failures:
            f.write(f"- {failure}\n")
    f.write("\n原始日志、fio JSON、DiagnosticSession 和 /proc 采样均保留；结论仅由本次有效实测数值决定。\n")

if errors or target_failures:
    if errors:
        print("[bench] invalid evidence:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
    if target_failures:
        print("[bench] performance acceptance failed:", file=sys.stderr)
        for failure in target_failures:
            print(f"  - {failure}", file=sys.stderr)
    raise SystemExit(1)
print(f"[bench] wrote {md_path}, {csv_path}, {json_path}")
PY
summary_status=$?
set -e

if (( summary_status != 0 )); then
  echo "[bench] evidence validation or performance acceptance failed; inspect $SUMMARY_JSON and $RAW_DIR" >&2
  exit "$summary_status"
fi
echo "[bench] complete: $SUMMARY_MD"
