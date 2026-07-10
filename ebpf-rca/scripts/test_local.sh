#!/usr/bin/env bash
# Local E2E test runner for ebpf-rca.
#
# The runner injects a workload, collects ebpf-rca JSON output, validates it
# with cmd/rca-testcheck, and stores all artifacts under test-results/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin/ebpf-rca"
CHECKER="$ROOT/bin/rca-testcheck"
TESTLOAD="$ROOT/bin/rca-testload"
SPEC="$ROOT/tests/scenarios.yaml"
STRESS_NG_BIN="${STRESS_NG:-}"

MODE="all"
SCENARIO=""
DURATION=""
OUT=""
NO_BUILD=0
KEEP_ARTIFACTS=0
IO_PATH=""
WORKLOAD_MODE=""
CLEANUP_PIDS=()
CLEANUP_PGIDS=()
CLEANUP_FILES=()
STARTED_WORKLOAD_PID=""
STARTED_WORKLOAD_PGID=""

usage() {
	cat <<'EOF'
Usage:
  bash scripts/test_local.sh [preflight|smoke|all|scenario|negative|report] [options]
  bash scripts/test_local.sh cpu|io|mem|lock|syscall|idle|normal_mem|normal_epoll|normal_io_sleep|normal_io_seq [options]

Options:
  --scenario NAME       Positive scenario, idle, or normal_mem|normal_epoll|normal_io_sleep|normal_io_seq
  --duration SECONDS    Workload duration in seconds, or with trailing s
  --out DIR             Artifact directory (default: test-results/<timestamp>)
  --io-path PATH        fio test image path (default: artifact dir)
  --workload MODE       deterministic|stress (default: deterministic; stress is an opt-in realism test)
  --no-build            Reuse existing bin/ebpf-rca and bin/rca-testcheck
  --keep-artifacts      Accepted for explicitness; artifacts are kept by default
  -h, --help            Show this help
EOF
}

if [ $# -gt 0 ]; then
	case "$1" in
	preflight|smoke|all|scenario|negative|report)
		MODE="$1"
		shift
		;;
	cpu|io|mem|lock|syscall|idle|normal_mem|normal_epoll|normal_io_sleep|normal_io_seq|idle_cpu|idle_io|idle_lock|idle_syscall)
		MODE="scenario"
		SCENARIO="$1"
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	esac
fi

while [ $# -gt 0 ]; do
	case "$1" in
	--scenario)
		SCENARIO="${2:-}"
		shift 2
		;;
	--duration)
		DURATION="${2:-}"
		shift 2
		;;
	--out)
		OUT="${2:-}"
		shift 2
		;;
	--io-path)
		IO_PATH="${2:-}"
		shift 2
		;;
	--workload)
		WORKLOAD_MODE="${2:-}"
		shift 2
		;;
	--no-build)
		NO_BUILD=1
		shift
		;;
	--keep-artifacts)
		KEEP_ARTIFACTS=1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

timestamp="$(date +%Y%m%d-%H%M%S)"
OUT="${OUT:-$ROOT/test-results/$timestamp}"
RUN_LOG="$OUT/run.log"
mkdir -p "$OUT"

log() {
	local line="[test-local] $*"
	printf '%s\n' "$line" >&2
	printf '%s\n' "$line" >>"$RUN_LOG"
}

fail() {
	log "FAIL: $*"
	exit 1
}

cleanup() {
	local pgid pid
	for pgid in "${CLEANUP_PGIDS[@]:-}"; do
		terminate_pgid "$pgid"
	done
	for pid in "${CLEANUP_PIDS[@]:-}"; do
		terminate_pid "$pid"
	done
	local f
	for f in "${CLEANUP_FILES[@]:-}"; do
		if [ -n "$f" ]; then
			if rm -f "$f" 2>/dev/null; then :; fi
		fi
	done
}

track_pid() {
	CLEANUP_PIDS+=("$1")
}

untrack_pid() {
	local wanted="$1" index
	for index in "${!CLEANUP_PIDS[@]}"; do
		if [ "${CLEANUP_PIDS[$index]}" = "$wanted" ]; then
			unset 'CLEANUP_PIDS[index]'
		fi
	done
}

track_pgid() {
	CLEANUP_PGIDS+=("$1")
}

untrack_pgid() {
	local wanted="$1" index
	for index in "${!CLEANUP_PGIDS[@]}"; do
		if [ "${CLEANUP_PGIDS[$index]}" = "$wanted" ]; then
			unset 'CLEANUP_PGIDS[index]'
		fi
	done
}

terminate_pid() {
	local pid="${1:-}" attempt
	case "$pid" in
	""|*[!0-9]*) return 0 ;;
	esac
	if ! kill -0 "$pid" 2>/dev/null; then
		return 0
	fi
	if kill -TERM "$pid" 2>/dev/null; then :; fi
	for ((attempt = 0; attempt < 20; attempt++)); do
		if ! kill -0 "$pid" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	if kill -KILL "$pid" 2>/dev/null; then :; fi
}

terminate_pgid() {
	local pgid="${1:-}" own_pgid attempt
	case "$pgid" in
	""|0|*[!0-9]*) return 0 ;;
	esac
	own_pgid="$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')"
	if [ "$pgid" = "$own_pgid" ]; then
		log "refusing to signal the test runner's own process group $pgid"
		return 1
	fi
	if ! kill -0 -- "-$pgid" 2>/dev/null; then
		return 0
	fi
	if kill -TERM -- "-$pgid" 2>/dev/null; then :; fi
	for ((attempt = 0; attempt < 20; attempt++)); do
		if ! kill -0 -- "-$pgid" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
	done
	if kill -KILL -- "-$pgid" 2>/dev/null; then :; fi
}

proc_start_time() {
	local pid="$1" stat rest state
	case "$pid" in
	""|*[!0-9]*) return 1 ;;
	esac
	[ -r "/proc/$pid/stat" ] || return 1
	stat="$(<"/proc/$pid/stat")"
	rest="${stat##*) }"
	state="${rest%% *}"
	[ "$state" != "Z" ] || return 1
	set -- $rest
	[ "$#" -ge 20 ] || return 1
	printf '%s\n' "${20}"
}

process_instance_is_live() {
	local pid="$1" want_start_time="$2" current
	[ -n "$want_start_time" ] || return 1
	current="$(proc_start_time "$pid")" || return 1
	[ "$current" = "$want_start_time" ]
}

track_file() {
	CLEANUP_FILES+=("$1")
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

duration_seconds() {
	local raw="$1"
	raw="${raw%s}"
	if [ -z "$raw" ]; then
		return 1
	fi
	case "$raw" in
	*[!0-9]*)
		return 1
		;;
	esac
	printf '%s\n' "$raw"
}

default_duration() {
	local sc="$1"
	if [ -n "$DURATION" ]; then
		duration_seconds "$DURATION" || fail "--duration must be seconds, got $DURATION"
		return
	fi
	case "$sc" in
	syscall) printf '20\n' ;;
	idle|normal_mem|normal_epoll|normal_io_sleep|normal_io_seq|idle_cpu|idle_io|idle_lock|idle_syscall) printf '15\n' ;;
	*) printf '30\n' ;;
	esac
}

is_negative_scenario() {
	case "$1" in
	idle|normal_mem|normal_epoll|normal_io_sleep|normal_io_seq|idle_cpu|idle_io|idle_lock|idle_syscall)
		return 0
		;;
	esac
	return 1
}

effective_workload_mode() {
	if [ -n "$WORKLOAD_MODE" ]; then
		case "$WORKLOAD_MODE" in
		deterministic|stress) printf '%s\n' "$WORKLOAD_MODE" ;;
		*) fail "--workload must be deterministic or stress, got $WORKLOAD_MODE" ;;
		esac
		return
	fi
	printf 'deterministic\n'
}

prepare_go_cache() {
	if [ -n "${GOCACHE:-}" ]; then
		mkdir -p "$GOCACHE"
		return
	fi
	local home_cache="${HOME:-}/.cache/go-build"
	if [ -n "${HOME:-}" ] && [ -d "$home_cache" ] && [ -w "$home_cache" ]; then
		return
	fi
	export GOCACHE="${TMPDIR:-/var/tmp}/go-cache"
	mkdir -p "$GOCACHE"
}

run_ebpf() {
	if [ "$(id -u)" -eq 0 ]; then
		"$BIN" "$@"
	else
		sudo -n "$BIN" "$@"
	fi
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || return 1
}

find_stress_ng() {
	if [ -n "$STRESS_NG_BIN" ] && [ -x "$STRESS_NG_BIN" ]; then
		return 0
	fi
	local local_bin="$ROOT/../.build_deps/bin/stress-ng"
	if [ -x "$local_bin" ]; then
		STRESS_NG_BIN="$local_bin"
		return 0
	fi
	if command -v stress-ng >/dev/null 2>&1; then
		STRESS_NG_BIN="$(command -v stress-ng)"
		return 0
	fi
	return 1
}

record_env() {
	{
		printf 'time=%s\n' "$(date -Iseconds)"
		printf 'root=%s\n' "$ROOT"
		printf 'mode=%s\n' "$MODE"
		printf 'scenario=%s\n' "$SCENARIO"
		uname -a
		if command -v go >/dev/null 2>&1; then go version 2>/dev/null; else printf 'go=missing\n'; fi
		if command -v clang >/dev/null 2>&1; then clang --version 2>/dev/null | sed -n '1,2p'; else printf 'clang=missing\n'; fi
		printf 'btf='
		[ -r /sys/kernel/btf/vmlinux ] && printf 'present\n' || printf 'missing\n'
		printf 'tracefs='
		[ -d /sys/kernel/tracing ] && printf '/sys/kernel/tracing\n' || printf 'missing\n'
	} >"$OUT/env.txt"
}

preflight() {
	local missing=0
	record_env
	log "artifact dir: $OUT"

	for cmd in go clang setsid timeout; do
		if ! need_cmd "$cmd"; then
			log "missing command: $cmd"
			missing=1
		fi
	done
	if [ ! -r /sys/kernel/btf/vmlinux ]; then
		log "missing readable /sys/kernel/btf/vmlinux"
		missing=1
	fi
	if [ ! -d /sys/kernel/tracing ] && [ ! -d /sys/kernel/debug/tracing ]; then
		log "missing tracefs/debugfs tracing directory"
		missing=1
	fi
	if [ "$(id -u)" -ne 0 ] && ! need_cmd sudo; then
		log "not root and sudo is unavailable"
		missing=1
	fi
	if [ "$(id -u)" -ne 0 ] && need_cmd sudo; then
		if ! sudo -n true >"$OUT/sudo-check.log" 2>&1; then
			log "sudo cannot run non-interactively; run this test as root or configure passwordless sudo"
			log "sudo diagnostic: $OUT/sudo-check.log"
			missing=1
		fi
	fi
	if [ "$missing" -eq 0 ]; then
		local kallsyms_cmd=(awk '$1 != "0000000000000000" && $1 != "00000000" { found=1; exit } END { exit !found }' /proc/kallsyms)
		if [ "$(id -u)" -eq 0 ]; then
			"${kallsyms_cmd[@]}" || { log "root cannot read non-zero /proc/kallsyms; lock classification is unavailable"; missing=1; }
		else
			sudo -n "${kallsyms_cmd[@]}" || { log "sudo cannot read non-zero /proc/kallsyms; check kernel.kptr_restrict"; missing=1; }
		fi
	fi
	if [ "$missing" -ne 0 ]; then
		return 1
	fi
	log "preflight passed"
}

preflight_for_scenario() {
	local sc="$1"
	local workload_mode="$2"
	case "$sc" in
	mem|syscall)
		[ -x "$TESTLOAD" ] || fail "missing executable $TESTLOAD; run make test-load or omit --no-build"
		need_cmd python3 || fail "python3 is required for workload operating-point validation"
		;;
	lock)
		[ -x "$TESTLOAD" ] || fail "missing executable $TESTLOAD; run make test-load or omit --no-build"
		need_cmd python3 || fail "python3 is required for the independent lock-address oracle"
		;;
	cpu)
		if [ "$workload_mode" = "deterministic" ]; then
			[ -x "$TESTLOAD" ] || fail "missing executable $TESTLOAD; run make test-load or omit --no-build"
		else
			find_stress_ng || fail "stress-ng is required for $sc; build local copy at ../.build_deps/bin/stress-ng or install system package"
		fi
		;;
	io)
		need_cmd fio || fail "fio is required for io"
		need_cmd python3 || fail "python3 is required for strict I/O session health validation"
		;;
	normal_mem|normal_epoll|normal_io_sleep|normal_io_seq)
		[ -x "$TESTLOAD" ] || fail "missing executable $TESTLOAD; run make test-load or omit --no-build"
		;;
	idle|idle_cpu|idle_io|idle_lock|idle_syscall)
		:
		;;
	report_all)
		:
		;;
	*)
		fail "unknown scenario: $sc"
		;;
	esac
}

ensure_build() {
	prepare_go_cache
	if [ "$NO_BUILD" -eq 0 ]; then
		log "building ebpf-rca"
		(cd "$ROOT" && make build)
		log "building rca-testcheck"
		(cd "$ROOT" && go build -o "$CHECKER" ./cmd/rca-testcheck)
		log "building rca-testload"
		(cd "$ROOT" && go build -o "$TESTLOAD" ./cmd/rca-testload)
	fi
	[ -x "$BIN" ] || fail "missing executable $BIN; run make build or omit --no-build"
	[ -x "$CHECKER" ] || fail "missing executable $CHECKER; run go build -buildvcs=false -o bin/rca-testcheck ./cmd/rca-testcheck"
	[ -x "$TESTLOAD" ] || fail "missing executable $TESTLOAD; run go build -buildvcs=false -o bin/rca-testload ./cmd/rca-testload"
}

set_tool_args() {
	local sc="$1"
	local seconds="$2"
	local tool_seconds=$((seconds + 5))
	if [ "$sc" = "io" ]; then
		# The positive I/O run starts after a two-second warmup.  Seven extra
		# seconds leave a full five-second drain window before health capture.
		tool_seconds=$((seconds + 7))
	fi
	# Accuracy uses the product operating point: all collectors, default
	# thresholds/sustain, and no target filter.
	TOOL_ARGS=(--scenario all --allow-partial=false --interval 1s --format json --duration "${tool_seconds}s")
	case "$sc" in
	cpu|io|mem|lock|syscall|idle|normal_mem|normal_epoll|normal_io_sleep|normal_io_seq|idle_cpu|idle_io|idle_lock|idle_syscall) ;;
	*)
		fail "unknown scenario: $sc"
		;;
	esac
}

start_isolated_workload() {
	local log_path="$1"
	local timeout_seconds="$2"
	shift 2
	STARTED_WORKLOAD_PID=""
	STARTED_WORKLOAD_PGID=""
	# setsid makes the wrapper and every workload descendant one independently
	# signalable process group. timeout bounds a broken workload without hiding
	# its non-zero status; unlike the old syscall path, rc=124 is never normalized.
	setsid timeout --signal=TERM --kill-after=2s "${timeout_seconds}s" "$@" >"$log_path" 2>&1 &
	STARTED_WORKLOAD_PID=$!
	STARTED_WORKLOAD_PGID=$!
	track_pgid "$STARTED_WORKLOAD_PGID"
}

start_background_workload() {
	local sc="$1"
	local seconds="$2"
	local workload_mode="${3:-deterministic}"
	local workload_log="$4"
	local timeout_seconds=$((seconds + 5))
	case "$sc" in
	cpu)
		if [ "$workload_mode" = "deterministic" ]; then
			start_isolated_workload "$workload_log" "$timeout_seconds" \
				"$TESTLOAD" cpu --duration "${seconds}s"
		else
			start_isolated_workload "$workload_log" "$timeout_seconds" \
				"$STRESS_NG_BIN" --cpu "$(nproc)" --cpu-method matrixprod \
				--timeout "${seconds}s" --metrics-brief
		fi
		;;
	io)
		local fio_path="${IO_PATH:-$OUT/fio-test.img}"
		track_file "$fio_path"
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			fio --name=rca-e2e-io --filename="$fio_path" --size="${IO_SIZE:-512M}" \
			--rw=randrw --rwmixread=70 --bs=4k --direct=1 --ioengine=libaio \
			--iodepth=64 --numjobs=4 --runtime="$seconds" --time_based \
			--group_reporting --output-format=json
		;;
	mem)
		local mem_args=(mem-pressure --duration "${seconds}s" \
			--workers "${MEM_WORKERS:-8}" \
			--fast-rate-mib "${MEM_FAST_RATE_MIB:-128}" \
			--pressure-rate-mib "${MEM_PRESSURE_RATE_MIB:-96}" \
			--target-available-pct "${MEM_TARGET_AVAILABLE_PCT:-10}")
		if [ -n "${MEM_MAX_BYTES:-}" ]; then
			mem_args+=(--max-bytes "$MEM_MAX_BYTES")
		fi
		start_isolated_workload "$workload_log" "$timeout_seconds" "$TESTLOAD" "${mem_args[@]}"
		;;
	lock)
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			"$TESTLOAD" lock --duration "${seconds}s" --threads 8
		;;
	syscall)
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			"$TESTLOAD" syscall --duration "${seconds}s" --rate "${SYSCALL_RATE:-30000}"
		;;
	normal_mem)
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			"$TESTLOAD" normal-mem --duration "${seconds}s" --bytes "${NORMAL_MEM_BYTES:-134217728}"
		;;
	normal_epoll)
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			"$TESTLOAD" epoll-wait --duration "${seconds}s"
		;;
	normal_io_sleep)
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			"$TESTLOAD" io-sleep --duration "${seconds}s" --interval "${NORMAL_IO_SLEEP_INTERVAL:-250ms}"
		;;
	normal_io_seq)
		local seq_path="${IO_PATH:-$OUT/normal-seq-direct.img}"
		track_file "$seq_path"
		start_isolated_workload "$workload_log" "$timeout_seconds" \
			"$TESTLOAD" seq-direct-io --duration "${seconds}s" --path "$seq_path" \
			--size "${NORMAL_IO_SIZE:-67108864}" --block-size "${NORMAL_IO_BLOCK_SIZE:-131072}" \
			--interval "${NORMAL_IO_INTERVAL:-10ms}"
		;;
	idle|idle_cpu|idle_io|idle_lock|idle_syscall)
		start_isolated_workload "$workload_log" "$timeout_seconds" sleep "$seconds"
		;;
	*)
		fail "unknown scenario: $sc"
		;;
	esac
}

validate_io_session_health() {
	local input="$1"
	python3 - "$input" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as stream:
        session = json.load(stream)
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"cannot read DiagnosticSession {path}: {exc}")

if not isinstance(session, dict) or not isinstance(session.get("collectors"), list):
    raise SystemExit("tool output is not a DiagnosticSession with collectors[]")
io_collectors = [item for item in session["collectors"] if isinstance(item, dict) and item.get("name") == "io"]
if len(io_collectors) != 1:
    raise SystemExit(f"expected exactly one io collector status, got {len(io_collectors)}")
health = io_collectors[0].get("health")
counters = health.get("counters") if isinstance(health, dict) else None
if not isinstance(counters, dict):
    raise SystemExit("io collector health.counters is missing")
for name in ("current_inflight", "completion_miss", "map_update_fail", "io_error"):
    value = counters.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise SystemExit(f"io collector counter {name} is missing or not an integer")
    if value != 0:
        raise SystemExit(f"io collector counter {name}={value}, want 0 after drain window")
print("PASS io health: inflight/completion_miss/map_update_fail/io_error all zero")
PY
}

validate_mem_workload_oracle() {
	local workload_log="$1" oracle_path="$2"
	python3 - "$workload_log" "$oracle_path" <<'PY'
import json
import sys
from pathlib import Path

workload_path, oracle_path = map(Path, sys.argv[1:])
lines = workload_path.read_text(encoding="utf-8", errors="strict").splitlines()

def records(prefix: str) -> list[dict[str, str]]:
    result = []
    for line in lines:
        parts = line.split()
        if not parts or parts[0] != prefix:
            continue
        fields = {}
        for token in parts[1:]:
            if "=" not in token:
                raise SystemExit(f"malformed {prefix} token: {token}")
            key, value = token.split("=", 1)
            fields[key] = value
        result.append(fields)
    return result

plans = records("mem_pressure_plan")
results = records("mem_pressure_result")
if len(plans) != 1:
    raise SystemExit(f"expected one mem_pressure_plan, got {len(plans)}")
plan = plans[0]
try:
    effective_workers = int(plan["effective_workers"])
    fast_rate = int(plan["fast_rate_mib_per_worker"])
    required_sustain = int(plan["required_sustain_seconds"])
except (KeyError, ValueError) as exc:
    raise SystemExit(f"invalid memory pressure plan: {exc}")
if not (1 <= effective_workers <= 64) or not (1 <= fast_rate <= 160) or required_sustain < 5:
    raise SystemExit(f"unsafe memory pressure plan: {plan}")

oracle = {
    "schema_version": "1.0",
    "effective_workers": effective_workers,
    "fast_rate_mib_per_worker": fast_rate,
    "required_sustain_seconds": required_sustain,
}
victim_pids = []
for line in lines:
    if not line.startswith("mem_pressure_oom_victim_pid="):
        continue
    first, *rest = line.split()
    try:
        pid = int(first.split("=", 1)[1])
    except (IndexError, ValueError) as exc:
        raise SystemExit(f"invalid OOM-victim oracle: {line}: {exc}")
    if "signal=SIGKILL" not in rest or pid <= 0:
        raise SystemExit(f"invalid OOM-victim oracle: {line}")
    victim_pids.append(pid)

if victim_pids:
    oracle.update({"mode": "oom", "oom_victim_pids": victim_pids})
else:
    if len(results) != 1:
        raise SystemExit(f"expected one worker-zero memory result, got {len(results)}")
    result = results[0]
    try:
        crossed = result["crossed_pressure"] == "true"
        min_available_pct = float(result["min_available_pct"])
        pressure_fault_seconds = float(result["pressure_fault_seconds"])
        touched_bytes = int(result["touched_bytes"])
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"invalid memory pressure result: {exc}")
    if not crossed or min_available_pct >= 15 or pressure_fault_seconds < required_sustain:
        raise SystemExit(
            f"memory workload did not reach/sustain pressure: crossed={crossed} "
            f"min_available_pct={min_available_pct} pressure_fault_seconds={pressure_fault_seconds}"
        )
    oracle.update({
        "mode": "pressure",
        "min_available_pct": min_available_pct,
        "pressure_fault_seconds": pressure_fault_seconds,
        "touched_bytes": touched_bytes,
    })

tmp = oracle_path.with_suffix(oracle_path.suffix + ".tmp")
tmp.write_text(json.dumps(oracle, sort_keys=True) + "\n", encoding="utf-8")
tmp.replace(oracle_path)
print(f"PASS memory workload oracle: mode={oracle['mode']} workers={effective_workers}")
PY
}

validate_syscall_workload_oracle() {
	local workload_log="$1" truth_path="$2" oracle_path="$3"
	python3 - "$workload_log" "$truth_path" "$oracle_path" <<'PY'
import json
import re
import sys
from pathlib import Path

workload_path, truth_path, oracle_path = map(Path, sys.argv[1:])
text = workload_path.read_text(encoding="utf-8", errors="strict")
matches = re.findall(
    r"^syscall_calls=([0-9]+) elapsed_seconds=([0-9]+(?:\.[0-9]+)?) "
    r"achieved_calls_per_sec=([0-9]+(?:\.[0-9]+)?) target_rate=([0-9]+)$",
    text,
    re.MULTILINE,
)
if len(matches) != 1:
    raise SystemExit(f"expected one syscall workload result, got {len(matches)}")
calls = int(matches[0][0])
elapsed = float(matches[0][1])
achieved = float(matches[0][2])
target = int(matches[0][3])
minimum = max(10000.0, target * 0.8)
if calls <= 0 or elapsed <= 0 or achieved < minimum:
    raise SystemExit(
        f"syscall injection below operating point: achieved={achieved:.2f}, require={minimum:.2f}"
    )
oracle = {
    "schema_version": "1.0",
    "syscall": "read",
    "calls": calls,
    "elapsed_seconds": elapsed,
    "achieved_calls_per_sec": achieved,
    "target_rate": target,
    "minimum_acceptable_rate": minimum,
}
truth = json.loads(truth_path.read_text(encoding="utf-8", errors="strict"))
if not isinstance(truth, dict) or truth.get("scenario") != "syscall":
    raise SystemExit("syscall ground truth is missing or has the wrong scenario")
truth["syscall"] = "read"
truth_tmp = truth_path.with_suffix(truth_path.suffix + ".tmp")
tmp = oracle_path.with_suffix(oracle_path.suffix + ".tmp")
truth_tmp.write_text(json.dumps(truth, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
tmp.write_text(json.dumps(oracle, sort_keys=True) + "\n", encoding="utf-8")
truth_tmp.replace(truth_path)
tmp.replace(oracle_path)
print(
    f"PASS syscall workload oracle: name=read achieved={achieved:.2f} calls/s "
    f"minimum={minimum:.2f}; name injected into ground truth"
)
PY
}

write_scenario_status() {
	local path="$1"
	local scenario="$2"
	local workload_rc="$3"
	local tool_rc="$4"
	local truth_rc="$5"
	local health_rc="$6"
	local checker_rc="$7"
	local tmp="${path}.tmp"
	printf '{"schema_version":"1.0","scenario":"%s","complete":true,"workload_rc":%d,"tool_rc":%d,"truth_rc":%d,"health_rc":%d,"checker_rc":%d}\n' \
		"$scenario" "$workload_rc" "$tool_rc" "$truth_rc" "$health_rc" "$checker_rc" >"$tmp"
	mv "$tmp" "$path"
}

wait_truth_or_fail_if_root_live() {
	local truth_pid="$1" workload_pid="$2" workload_start_time="$3" workload_pgid="$4" truth_log="$5" rc
	wait "$truth_pid"
	rc=$?
	untrack_pid "$truth_pid"
	if [ "$rc" -eq 0 ] && process_instance_is_live "$workload_pid" "$workload_start_time"; then
		printf 'truth watcher reached its deadline while root pid %s was still alive\n' \
			"$workload_pid" >>"$truth_log"
		terminate_pgid "$workload_pgid"
		return 124
	fi
	return "$rc"
}

validate_lock_workload_oracle() {
	local workload_log="$1" truth_path="$2" oracle_path="$3"
	python3 - "$workload_log" "$truth_path" "$oracle_path" <<'PY'
import json
import re
import sys
from pathlib import Path

workload_path, truth_path, oracle_path = map(Path, sys.argv[1:])
text = workload_path.read_text(encoding="utf-8", errors="strict")
headers = re.findall(r"^lock_address=(0x[0-9a-fA-F]+) waiter_threads=([0-9]+)$", text, re.MULTILINE)
tid_lines = re.findall(r"^lock_waiter_tids=([0-9]+(?:,[0-9]+)*)$", text, re.MULTILINE)
stats = re.findall(
    r"^lock_acquisitions=([0-9]+) futex_wait_calls=([0-9]+) "
    r"futex_wake_calls=([0-9]+) distinct_waiter_tids=([0-9]+)$",
    text,
    re.MULTILINE,
)
if len(headers) != 1 or len(tid_lines) != 1 or len(stats) != 1:
    raise SystemExit("lock workload did not emit exactly one complete futex oracle")
address = int(headers[0][0], 16)
waiter_threads = int(headers[0][1])
tids = [int(value) for value in tid_lines[0].split(",")]
acquisitions, waits, wakes, distinct = map(int, stats[0])
if address == 0 or waiter_threads < 2:
    raise SystemExit("lock workload oracle has a zero address or fewer than two waiters")
if len(set(tids)) != waiter_threads or distinct != waiter_threads:
    raise SystemExit(
        f"lock workload waiter identity mismatch: configured={waiter_threads} "
        f"listed={len(set(tids))} reported={distinct}"
    )
if waits < waiter_threads or wakes == 0 or acquisitions <= waiter_threads:
    raise SystemExit(
        f"lock workload did not establish sustained futex contention: "
        f"acquisitions={acquisitions} waits={waits} wakes={wakes}"
    )

truth = json.loads(truth_path.read_text(encoding="utf-8", errors="strict"))
if not isinstance(truth, dict) or truth.get("scenario") != "lock":
    raise SystemExit("lock ground truth is missing or has the wrong scenario")
allowed_tids = truth.get("allowed_tids")
if not isinstance(allowed_tids, list) or any(
    isinstance(tid, bool) or not isinstance(tid, int) or tid <= 0 for tid in allowed_tids
):
    raise SystemExit("lock ground truth has invalid allowed_tids")
missing_tids = sorted(set(tids) - set(allowed_tids))
if missing_tids:
    raise SystemExit(f"lock ground truth missed workload waiter tids: {missing_tids}")
truth["lock_address"] = address

oracle = {
    "schema_version": "1.0",
    "lock_address": address,
    "lock_address_hex": f"0x{address:x}",
    "waiter_threads": waiter_threads,
    "waiter_tids": tids,
    "acquisitions": acquisitions,
    "futex_wait_calls": waits,
    "futex_wake_calls": wakes,
}
truth_tmp = truth_path.with_suffix(truth_path.suffix + ".tmp")
oracle_tmp = oracle_path.with_suffix(oracle_path.suffix + ".tmp")
truth_tmp.write_text(json.dumps(truth, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
oracle_tmp.write_text(json.dumps(oracle, sort_keys=True) + "\n", encoding="utf-8")
truth_tmp.replace(truth_path)
oracle_tmp.replace(oracle_path)
print(
    f"PASS lock workload oracle: address=0x{address:x} waiters={waiter_threads} "
    f"wait_calls={waits}; address injected into ground truth"
)
PY
}

run_json_scenario() {
	local sc="$1"
	local seconds
	seconds="$(default_duration "$sc")"
	local workload_mode
	workload_mode="$(effective_workload_mode)"
	case "$sc" in
	normal_mem|normal_epoll|normal_io_sleep|normal_io_seq)
		# Negative controls are fixed testload programs; the positive workload
		# selector must not silently substitute stress-ng/fio variants.
		workload_mode="deterministic"
		;;
	esac
	preflight_for_scenario "$sc" "$workload_mode"

	local dir="$OUT/$sc"
	local json="$dir/output.json"
	local stderr="$dir/ebpf-rca.stderr"
	local workload_log="$dir/workload.log"
	local summary="$dir/check.json"
	local truth="$dir/ground_truth.json"
	local truth_log="$dir/ground_truth.log"
	local truth_rc=0
	local health_rc=0
	local io_file=""
	mkdir -p "$dir"
	if [ "$sc" = "io" ]; then
		io_file="${IO_PATH:-$OUT/fio-test.img}"
	fi

	log "scenario=$sc duration=${seconds}s workload=$workload_mode"
	local tool_pid=""
	local workload_pid=""
	local workload_start_time=""
	local workload_pgid=""
	local truth_pid=""

	# Attach every collector before injecting the workload.  This is essential
	# for one-shot events (OOM victim selection) and avoids losing the first
	# futex/syscall transitions to a late attach.
	set_tool_args "$sc" "$seconds"
	log "starting ebpf-rca: ${TOOL_ARGS[*]}"
	set +e
	run_ebpf "${TOOL_ARGS[@]}" >"$json" 2>"$stderr" &
	tool_pid=$!
	track_pid "$tool_pid"
	set -e

	sleep 2
	log "starting workload for $sc"
	start_background_workload "$sc" "$seconds" "$workload_mode" "$workload_log"
	workload_pid="$STARTED_WORKLOAD_PID"
	workload_pgid="$STARTED_WORKLOAD_PGID"
	if ! workload_start_time="$(proc_start_time "$workload_pid")"; then
		workload_start_time=""
	fi

	if ! is_negative_scenario "$sc"; then
		log "recording ground truth for $sc root_pid=$workload_pid"
		local truth_args=(--write-truth --watch --watch-timeout "$((seconds + 5))s" --scenario "$sc" --root-pid "$workload_pid" --truth "$truth")
		if [ "$sc" = "io" ]; then
			truth_args+=(--io-file "$io_file")
		fi
		set +e
		"$CHECKER" "${truth_args[@]}" >"$truth_log" 2>&1 &
		truth_pid=$!
		track_pid "$truth_pid"
		set -e
	fi

	set +e
	if [ -n "$truth_pid" ]; then
		wait_truth_or_fail_if_root_live "$truth_pid" "$workload_pid" "$workload_start_time" \
			"$workload_pgid" "$truth_log"
		truth_rc=$?
	fi
	wait "$workload_pid"
	local workload_rc=$?
	untrack_pgid "$workload_pgid"
	wait "$tool_pid"
	local tool_rc=$?
	untrack_pid "$tool_pid"
	set -e
	if [ "$sc" = "io" ] && [ "$tool_rc" -eq 0 ]; then
		set +e
		validate_io_session_health "$json" >"$dir/io-health.log" 2>&1
		health_rc=$?
		set -e
	fi
	if [ "$sc" = "mem" ] && [ "$workload_rc" -eq 0 ]; then
		set +e
		validate_mem_workload_oracle "$workload_log" "$dir/mem-oracle.json" \
			>"$dir/mem-oracle.log" 2>&1
		health_rc=$?
		set -e
	fi
	if [ "$sc" = "lock" ] && [ "$workload_rc" -eq 0 ] && [ "$truth_rc" -eq 0 ]; then
		set +e
		validate_lock_workload_oracle "$workload_log" "$truth" "$dir/lock-oracle.json" \
			>"$dir/lock-oracle.log" 2>&1
		health_rc=$?
		set -e
	fi
	if [ "$sc" = "syscall" ] && [ "$workload_rc" -eq 0 ] && [ "$truth_rc" -eq 0 ]; then
		set +e
		validate_syscall_workload_oracle "$workload_log" "$truth" "$dir/syscall-oracle.json" \
			>"$dir/syscall-oracle.log" 2>&1
		health_rc=$?
		set -e
	fi

	if [ "$workload_rc" -ne 0 ]; then
		log "workload for $sc exited with $workload_rc; see $workload_log"
	fi
	if [ "$tool_rc" -ne 0 ]; then
		log "ebpf-rca for $sc exited with $tool_rc; see $stderr"
	fi
	if [ "$truth_rc" -ne 0 ]; then
		log "ground truth capture for $sc failed; see $truth_log"
	fi
	if [ "$health_rc" -ne 0 ]; then
		log "scenario integrity postcondition failed for $sc; see $dir/*-health.log or $dir/*-oracle.log"
	fi

	local check_rc=125
	if [ "$truth_rc" -eq 0 ]; then
		log "validating $sc"
		local check_args=(--spec "$SPEC" --scenario "$sc" --input "$json" --summary "$summary" --require-session-all)
		if ! is_negative_scenario "$sc"; then
			check_args+=(--truth "$truth")
		fi
		set +e
		"$CHECKER" "${check_args[@]}" >"$dir/check.log" 2>&1
		check_rc=$?
		set -e
		if [ "$check_rc" -ne 0 ]; then
			log "validation failed for $sc; see $dir/check.log"
		fi
	fi
	write_scenario_status "$dir/run_status.json" "$sc" "$workload_rc" "$tool_rc" "$truth_rc" "$health_rc" "$check_rc"
	if [ "$workload_rc" -ne 0 ] || [ "$tool_rc" -ne 0 ] || [ "$truth_rc" -ne 0 ] || [ "$health_rc" -ne 0 ] || [ "$check_rc" -ne 0 ]; then
		return 1
	fi
	log "scenario $sc passed"
}

run_report() {
	local seconds
	seconds="$(default_duration cpu)"
	local workload_mode
	workload_mode="$(effective_workload_mode)"
	preflight_for_scenario cpu "$workload_mode"
	preflight_for_scenario syscall "$workload_mode"

	local dir="$OUT/report_all"
	local report="$dir/report.md"
	local stderr="$dir/ebpf-rca.stderr"
	local stdout="$dir/ebpf-rca.stdout"
	local summary="$dir/check.json"
	local cpu_truth="$dir/ground_truth_cpu.json"
	local syscall_truth="$dir/ground_truth_syscall.json"
	local cpu_truth_log="$dir/ground_truth_cpu.log"
	local syscall_truth_log="$dir/ground_truth_syscall.log"
	mkdir -p "$dir"

	local tool_seconds=$((seconds + 5))
	log "starting report mode duration=${seconds}s workload=$workload_mode"

	start_background_workload syscall "$seconds" "$workload_mode" "$dir/workload_syscall.log"
	local syscall_pid="$STARTED_WORKLOAD_PID"
	local syscall_pgid="$STARTED_WORKLOAD_PGID"
	local syscall_start_time=""
	if ! syscall_start_time="$(proc_start_time "$syscall_pid")"; then
		syscall_start_time=""
	fi

	set +e
	"$CHECKER" --write-truth --watch --watch-timeout "$((seconds + 5))s" --scenario syscall --root-pid "$syscall_pid" --truth "$syscall_truth" >"$syscall_truth_log" 2>&1 &
	local syscall_truth_pid=$!
	track_pid "$syscall_truth_pid"
	run_ebpf --scenario all --report "$report" --duration "${tool_seconds}s" >"$stdout" 2>"$stderr" &
	local tool_pid=$!
	track_pid "$tool_pid"
	set -e

	sleep 2
	set +e
	start_background_workload cpu "$seconds" "$workload_mode" "$dir/workload_cpu.log"
	local cpu_pid="$STARTED_WORKLOAD_PID"
	local cpu_pgid="$STARTED_WORKLOAD_PGID"
	local cpu_start_time=""
	if ! cpu_start_time="$(proc_start_time "$cpu_pid")"; then
		cpu_start_time=""
	fi
	"$CHECKER" --write-truth --watch --watch-timeout "$((seconds + 5))s" --scenario cpu --root-pid "$cpu_pid" --truth "$cpu_truth" >"$cpu_truth_log" 2>&1 &
	local cpu_truth_pid=$!
	track_pid "$cpu_truth_pid"
	wait_truth_or_fail_if_root_live "$cpu_truth_pid" "$cpu_pid" "$cpu_start_time" "$cpu_pgid" "$cpu_truth_log"
	local cpu_truth_rc=$?
	wait_truth_or_fail_if_root_live "$syscall_truth_pid" "$syscall_pid" "$syscall_start_time" "$syscall_pgid" "$syscall_truth_log"
	local syscall_truth_rc=$?
	wait "$cpu_pid"
	local cpu_rc=$?
	untrack_pgid "$cpu_pgid"
	wait "$syscall_pid"
	local syscall_rc=$?
	untrack_pgid "$syscall_pgid"
	wait "$tool_pid"
	local tool_rc=$?
	untrack_pid "$tool_pid"
	set -e

	if [ "$cpu_rc" -ne 0 ]; then
		log "report cpu workload exited with $cpu_rc"
	fi
	if [ "$syscall_rc" -ne 0 ]; then
		log "report syscall workload exited with $syscall_rc"
	fi
	if [ "$tool_rc" -ne 0 ]; then
		log "report ebpf-rca exited with $tool_rc"
	fi
	if [ "$cpu_truth_rc" -ne 0 ]; then
		log "report cpu truth capture exited with $cpu_truth_rc; see $cpu_truth_log"
	fi
	if [ "$syscall_truth_rc" -ne 0 ]; then
		log "report syscall truth capture exited with $syscall_truth_rc; see $syscall_truth_log"
	fi

	set +e
	"$CHECKER" --spec "$SPEC" --scenario report_all --report "$report" --truth "cpu=$cpu_truth" --truth "syscall=$syscall_truth" --summary "$summary" >"$dir/check.log" 2>&1
	local check_rc=$?
	set -e
	if [ "$check_rc" -ne 0 ]; then
		log "report validation failed; see $dir/check.log"
		return 1
	fi
	if [ "$cpu_rc" -ne 0 ] || [ "$syscall_rc" -ne 0 ] || [ "$tool_rc" -ne 0 ] || [ "$cpu_truth_rc" -ne 0 ] || [ "$syscall_truth_rc" -ne 0 ]; then
		return 1
	fi
	log "report mode passed"
}

run_scenarios() {
	local failed=0
	for sc in "$@"; do
		if ! run_json_scenario "$sc"; then
			failed=1
		fi
	done
	return "$failed"
}

main() {
	log "starting local test runner"
	preflight || fail "preflight failed; see $OUT/env.txt and $RUN_LOG"
	if [ "$MODE" = "preflight" ]; then
		log "preflight only complete"
		return 0
	fi

	ensure_build

	case "$MODE" in
	smoke)
		run_scenarios cpu syscall
		;;
	all)
		run_scenarios cpu io mem lock syscall
		;;
	scenario)
		[ -n "$SCENARIO" ] || fail "--scenario is required for mode=scenario"
		if [ "$SCENARIO" = "all" ]; then
			run_scenarios cpu io mem lock syscall
		else
			run_scenarios "$SCENARIO"
		fi
		;;
	negative)
		run_scenarios idle normal_mem normal_epoll normal_io_sleep normal_io_seq
		;;
	report)
		run_report
		;;
	*)
		fail "unknown mode: $MODE"
		;;
	esac
	log "all requested tests passed; artifacts: $OUT"
}

main

# Keep this variable referenced so shellcheck does not treat it as stale when
# users pass it for scripts that wrap this runner.
_="$KEEP_ARTIFACTS"
