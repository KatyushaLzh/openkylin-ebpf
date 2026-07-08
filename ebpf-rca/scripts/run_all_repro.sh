#!/usr/bin/env bash
# 五类异常一键复现 + 结构化输出留档。
# 注意：本脚本只内置纯 workload，不调用 scripts/repro_*.sh；那些脚本本身会启动 ebpf-rca。

set -u

DURATION="60"
OUT_DIR="outputs/repro"
TOOL="./bin/ebpf-rca"
SUDO="sudo"
FORMAT="json"
INTERVAL="1s"
WARMUP="3"
MARGIN="5"
SCENARIOS=(cpu io mem lock syscall)
STRESS_NG_BIN="${STRESS_NG:-}"

usage() {
  cat <<USAGE
Usage: bash scripts/run_all_repro.sh [options]

Options:
  --duration seconds      workload duration, default: 60
  --out DIR               default: outputs/repro
  --tool PATH             default: ./bin/ebpf-rca
  --format json|yaml|md   default: json
  --interval DURATION     default: 1s
  --warmup seconds        delay between tool start and workload start, default: 3
  --margin seconds        extra tool runtime after workload, default: 5
  --no-sudo               run tool without sudo
  -h|--help               show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DURATION="${2:-}"; shift 2;;
    --out) OUT_DIR="${2:-}"; shift 2;;
    --tool) TOOL="${2:-}"; shift 2;;
    --format) FORMAT="${2:-}"; shift 2;;
    --interval) INTERVAL="${2:-}"; shift 2;;
    --warmup) WARMUP="${2:-}"; shift 2;;
    --margin) MARGIN="${2:-}"; shift 2;;
    --no-sudo) SUDO=""; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

duration_seconds() {
  local raw="$1"
  raw="${raw%s}"
  case "$raw" in
    ""|*[!0-9]*) return 1;;
  esac
  printf '%s\n' "$raw"
}

DURATION_SEC="$(duration_seconds "$DURATION")" || {
  echo "--duration must be seconds, got $DURATION" >&2
  exit 2
}
WARMUP_SEC="$(duration_seconds "$WARMUP")" || {
  echo "--warmup must be seconds, got $WARMUP" >&2
  exit 2
}
MARGIN_SEC="$(duration_seconds "$MARGIN")" || {
  echo "--margin must be seconds, got $MARGIN" >&2
  exit 2
}
TOOL_DURATION_SEC=$((DURATION_SEC + WARMUP_SEC + MARGIN_SEC))

mkdir -p "$OUT_DIR" "$OUT_DIR/raw"
SUMMARY="$OUT_DIR/repro_summary.md"
CSV="$OUT_DIR/repro_summary.csv"

CLEANUP_PIDS=()

cleanup() {
  local pid
  for pid in "${CLEANUP_PIDS[@]:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

track_pid() {
  CLEANUP_PIDS+=("$1")
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

find_stress_ng() {
  if [[ -n "$STRESS_NG_BIN" && -x "$STRESS_NG_BIN" ]]; then
    return 0
  fi
  local local_bin="./../.build_deps/bin/stress-ng"
  if [[ -x "$local_bin" ]]; then
    STRESS_NG_BIN="$local_bin"
    return 0
  fi
  if need_cmd stress-ng; then
    STRESS_NG_BIN="$(command -v stress-ng)"
    return 0
  fi
  return 1
}

nproc_safe() {
  if need_cmd nproc; then
    nproc
  else
    printf '1\n'
  fi
}

run_workload() {
  local scenario="$1" seconds="$2" log="$3"
  {
    echo "[workload] scenario=$scenario duration=${seconds}s"
    case "$scenario" in
      cpu)
        if ! find_stress_ng; then
          echo "stress-ng not found; run make deps or install stress-ng" >&2
          return 127
        fi
        "$STRESS_NG_BIN" --cpu "$(nproc_safe)" --cpu-method matrixprod --timeout "${seconds}s" --metrics-brief
        ;;
      io)
        if ! need_cmd fio; then
          echo "fio not found; run make deps or install fio" >&2
          return 127
        fi
        local fio_path="${IO_PATH:-$OUT_DIR/raw/io-fio-test.img}"
        fio --name=rca-score-io --filename="$fio_path" --size="${IO_SIZE:-512M}" \
          --rw=randrw --rwmixread=70 --bs=4k --iodepth=32 --numjobs=2 \
          --runtime="$seconds" --time_based --group_reporting
        local rc=$?
        rm -f "$fio_path"
        return "$rc"
        ;;
      mem)
        if ! find_stress_ng; then
          echo "stress-ng not found; run make deps or install stress-ng" >&2
          return 127
        fi
        "$STRESS_NG_BIN" --vm 2 --vm-bytes "${MEM_BYTES:-80%}" --vm-keep --timeout "${seconds}s" --metrics-brief
        ;;
      lock)
        if ! find_stress_ng; then
          echo "stress-ng not found; run make deps or install stress-ng" >&2
          return 127
        fi
        if "$STRESS_NG_BIN" --help 2>/dev/null | grep -q -- '--mutex'; then
          "$STRESS_NG_BIN" --mutex 8 --timeout "${seconds}s" --metrics-brief
        else
          "$STRESS_NG_BIN" --futex 8 --timeout "${seconds}s" --metrics-brief
        fi
        ;;
      syscall)
        if ! need_cmd timeout || ! need_cmd dd; then
          echo "timeout and dd are required for syscall workload" >&2
          return 127
        fi
        timeout "${seconds}s" dd if=/dev/zero of=/dev/null bs=1 count=200000000
        local rc=$?
        if [[ "$rc" -eq 124 ]]; then
          return 0
        fi
        return "$rc"
        ;;
      *)
        echo "unknown scenario: $scenario" >&2
        return 2
        ;;
    esac
  } >"$log" 2>&1
}

tool_args_for_scenario() {
  local scenario="$1" output="$2"
  TOOL_ARGS=(
    "$TOOL"
    --scenario "$scenario"
    --interval "$INTERVAL"
    --sustain 1
    --duration "${TOOL_DURATION_SEC}s"
    --format "$FORMAT"
    --output "$output"
  )
  case "$scenario" in
    cpu) TOOL_ARGS+=(--threshold 0.80);;
    io) TOOL_ARGS+=(--threshold 0.50);;
    mem) TOOL_ARGS+=(--threshold 40);;
    lock) TOOL_ARGS+=(--threshold 0.10);;
    syscall) TOOL_ARGS+=(--threshold 1000);;
  esac
}

start_tool() {
  local log="$1"
  if [[ -n "$SUDO" ]]; then
    "$SUDO" -n "${TOOL_ARGS[@]}" >"$log" 2>&1 &
  else
    "${TOOL_ARGS[@]}" >"$log" 2>&1 &
  fi
  printf '%s\n' "$!"
}

require_tool_privileges() {
  if [[ -n "$SUDO" && "$(id -u)" -ne 0 ]]; then
    if ! "$SUDO" -n true >/dev/null 2>&1; then
      echo "[repro] sudo cannot run non-interactively." >&2
      echo "[repro] Rerun as root, configure passwordless sudo, or use --no-sudo only when the process already has CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE." >&2
      return 1
    fi
  fi
  return 0
}

wait_or_stop() {
  local pid="$1" limit="$2"
  local i
  for i in $(seq 1 "$limit"); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      wait "$pid" >/dev/null 2>&1 || true
      return 0
    fi
    sleep 1
  done
  kill "$pid" >/dev/null 2>&1 || true
  sleep 1
  kill -9 "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

echo 'scenario,status,tool_output,workload_log,started_at,ended_at,note' >"$CSV"
{
  echo '# ebpf-rca 五类异常复现报告'
  echo
  echo "- 生成时间：$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- workload duration：${DURATION_SEC}s"
  echo "- tool duration：${TOOL_DURATION_SEC}s"
  echo
  echo '| 场景 | 状态 | 工具输出 | 负载日志 | 说明 |'
  echo '|---|---|---|---|---|'
} >"$SUMMARY"

run_one() {
  local scenario="$1"
  local ext="$FORMAT"
  [[ "$FORMAT" == "yml" ]] && ext="yaml"
  [[ "$FORMAT" == "markdown" ]] && ext="md"
  local out="$OUT_DIR/${scenario}_report.${ext}"
  local tool_log="$OUT_DIR/raw/${scenario}_tool.log"
  local workload_log="$OUT_DIR/raw/${scenario}_workload.log"
  local started ended status note pid workload_status

  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  rm -f "$out" "$tool_log" "$workload_log"

  echo "[repro] $scenario: start ebpf-rca for ${TOOL_DURATION_SEC}s"
  tool_args_for_scenario "$scenario" "$out"
  pid="$(start_tool "$tool_log")"
  track_pid "$pid"
  sleep "$WARMUP_SEC"

  if ! kill -0 "$pid" >/dev/null 2>&1; then
    wait "$pid" >/dev/null 2>&1 || true
    ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    status="FAIL"
    note="tool exited before workload; see raw logs"
    printf '%s,%s,%s,%s,%s,%s,"%s"\n' "$scenario" "$status" "$out" "$workload_log" "$started" "$ended" "$note" >>"$CSV"
    printf '| %s | %s | `%s` | `%s` | %s |\n' "$scenario" "$status" "$out" "$workload_log" "$note" >>"$SUMMARY"
    return
  fi

  echo "[repro] $scenario: run pure workload"
  run_workload "$scenario" "$DURATION_SEC" "$workload_log"
  workload_status=$?

  wait_or_stop "$pid" "$((MARGIN_SEC + WARMUP_SEC + 5))"
  ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [[ -s "$out" && "$workload_status" -eq 0 ]]; then
    status="PASS"
    note="tool output generated"
  elif [[ -s "$out" ]]; then
    status="WARN"
    note="tool output generated, workload exit=$workload_status"
  else
    status="FAIL"
    note="no tool output; see raw logs"
  fi

  printf '%s,%s,%s,%s,%s,%s,"%s"\n' "$scenario" "$status" "$out" "$workload_log" "$started" "$ended" "$note" >>"$CSV"
  printf '| %s | %s | `%s` | `%s` | %s |\n' "$scenario" "$status" "$out" "$workload_log" "$note" >>"$SUMMARY"
}

require_tool_privileges || exit 2

for scenario in "${SCENARIOS[@]}"; do
  run_one "$scenario"
done

{
  echo
  echo '## 使用说明'
  echo
  echo '1. 将 `*_report.json` 作为技术报告第 4.1 节的实际输出样例。'
  echo '2. 将 `raw/*_workload.log` 作为异常注入证据。'
  echo '3. 运行 `python3 scripts/validate_report.py outputs/repro/*.json` 检查结构化字段和证据链。'
} >>"$SUMMARY"

echo "[repro] wrote $SUMMARY and $CSV"
