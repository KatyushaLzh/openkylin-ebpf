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
CLEANUP_FILES=()
STARTED_WORKLOAD_PID=""
STARTED_KILLER_PID=""

usage() {
	cat <<'EOF'
Usage:
  bash scripts/test_local.sh [preflight|smoke|all|scenario|negative|report] [options]
  bash scripts/test_local.sh cpu|io|mem|lock|syscall|idle|idle_cpu|idle_io|idle_lock|idle_syscall [options]

Options:
  --scenario NAME       Scenario for mode=scenario: cpu|io|mem|lock|syscall|all|idle*
  --duration SECONDS    Workload duration in seconds, or with trailing s
  --out DIR             Artifact directory (default: test-results/<timestamp>)
  --io-path PATH        fio test image path (default: artifact dir)
  --workload MODE       deterministic|stress (default: smoke/report=deterministic, all=scenario=stress)
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
	cpu|io|mem|lock|syscall|idle|idle_cpu|idle_io|idle_lock|idle_syscall)
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
	local pid
	for pid in "${CLEANUP_PIDS[@]:-}"; do
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null || true
		fi
	done
	local f
	for f in "${CLEANUP_FILES[@]:-}"; do
		if [ -n "$f" ]; then
			rm -f "$f" 2>/dev/null || true
		fi
	done
}

trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

track_pid() {
	CLEANUP_PIDS+=("$1")
}

track_file() {
	CLEANUP_FILES+=("$1")
}

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
	idle) printf '15\n' ;;
	*) printf '30\n' ;;
	esac
}

effective_workload_mode() {
	if [ -n "$WORKLOAD_MODE" ]; then
		case "$WORKLOAD_MODE" in
		deterministic|stress) printf '%s\n' "$WORKLOAD_MODE" ;;
		*) fail "--workload must be deterministic or stress, got $WORKLOAD_MODE" ;;
		esac
		return
	fi
	case "$MODE" in
	smoke|report) printf 'deterministic\n' ;;
	*) printf 'stress\n' ;;
	esac
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
		sudo "$BIN" "$@"
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
		go version 2>/dev/null || true
		clang --version 2>/dev/null | sed -n '1,2p' || true
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

	for cmd in go clang; do
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
	if [ "$missing" -ne 0 ]; then
		return 1
	fi
	log "preflight passed"
}

preflight_for_scenario() {
	local sc="$1"
	local workload_mode="$2"
	case "$sc" in
	cpu|lock|syscall)
		if [ "$workload_mode" = "deterministic" ]; then
			[ -x "$TESTLOAD" ] || fail "missing executable $TESTLOAD; run make test-load or omit --no-build"
		else
			case "$sc" in
			cpu|lock)
				find_stress_ng || fail "stress-ng is required for $sc; build local copy at ../.build_deps/bin/stress-ng or install system package"
				;;
			syscall)
				need_cmd timeout || fail "timeout is required for syscall"
				need_cmd dd || fail "dd is required for syscall"
				;;
			esac
		fi
		;;
	mem)
		find_stress_ng || fail "stress-ng is required for $sc; build local copy at ../.build_deps/bin/stress-ng or install system package"
		;;
	io)
		need_cmd fio || fail "fio is required for io"
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
	TOOL_ARGS=(--interval 1s --format json --duration "${tool_seconds}s")
	case "$sc" in
	cpu)
		TOOL_ARGS+=(--scenario cpu --threshold 0.80 --sustain 2)
		;;
	io)
		TOOL_ARGS+=(--scenario io --threshold 0.50 --sustain 1)
		;;
	mem)
		TOOL_ARGS+=(--scenario mem --threshold 40 --sustain 1)
		;;
	lock)
		TOOL_ARGS+=(--scenario lock --threshold 0.10 --sustain 1)
		;;
	syscall)
		TOOL_ARGS+=(--scenario syscall --threshold 1000 --sustain 1)
		;;
	idle|idle_cpu)
		TOOL_ARGS+=(--scenario cpu --threshold 0.95 --sustain 3)
		;;
	idle_io)
		TOOL_ARGS+=(--scenario io --threshold 5 --sustain 2)
		;;
	idle_lock)
		TOOL_ARGS+=(--scenario lock --threshold 0.30 --sustain 2)
		;;
	idle_syscall)
		TOOL_ARGS+=(--scenario syscall --threshold 10000 --sustain 2)
		;;
	*)
		fail "unknown scenario: $sc"
		;;
	esac
}

run_workload() {
	local sc="$1"
	local seconds="$2"
	local workload_mode="${3:-stress}"
	case "$sc" in
	cpu)
		if [ "$workload_mode" = "deterministic" ]; then
			"$TESTLOAD" cpu --duration "${seconds}s"
		else
			"$STRESS_NG_BIN" --cpu "$(nproc)" --cpu-method matrixprod --timeout "${seconds}s" --metrics-brief
		fi
		;;
	io)
		local fio_path="${IO_PATH:-$OUT/fio-test.img}"
		track_file "$fio_path"
		fio --name=rca-e2e-io --filename="$fio_path" --size="${IO_SIZE:-512M}" \
			--rw=randrw --rwmixread=70 --bs=4k --iodepth=32 --numjobs=2 \
			--runtime="$seconds" --time_based --group_reporting
		local rc=$?
		rm -f "$fio_path"
		return "$rc"
		;;
	mem)
		"$STRESS_NG_BIN" --vm 2 --vm-bytes "${MEM_BYTES:-80%}" --vm-keep --timeout "${seconds}s" --metrics-brief
		;;
	lock)
		if [ "$workload_mode" = "deterministic" ]; then
			"$TESTLOAD" lock --duration "${seconds}s" --threads 8
		else
			if "$STRESS_NG_BIN" --help 2>/dev/null | grep -q -- '--mutex'; then
				"$STRESS_NG_BIN" --mutex 8 --timeout "${seconds}s" --metrics-brief
			else
				"$STRESS_NG_BIN" --futex 8 --timeout "${seconds}s" --metrics-brief
			fi
		fi
		;;
	syscall)
		if [ "$workload_mode" = "deterministic" ]; then
			"$TESTLOAD" syscall --duration "${seconds}s"
		else
			timeout "${seconds}s" dd if=/dev/zero of=/dev/null bs=1 count=200000000
			local rc=$?
			if [ "$rc" -eq 124 ]; then
				return 0
			fi
			return "$rc"
		fi
		;;
	idle|idle_cpu|idle_io|idle_lock|idle_syscall)
		sleep "$seconds"
		;;
	*)
		fail "unknown scenario: $sc"
		;;
	esac
}

start_syscall_workload() {
	local seconds="$1"
	local workload_mode="$2"
	local workload_log="$3"
	STARTED_WORKLOAD_PID=""
	STARTED_KILLER_PID=""
	set +e
	if [ "$workload_mode" = "deterministic" ]; then
		"$TESTLOAD" syscall --duration "${seconds}s" >"$workload_log" 2>&1 &
	else
		dd if=/dev/zero of=/dev/null bs=1 count=200000000 >"$workload_log" 2>&1 &
	fi
	STARTED_WORKLOAD_PID=$!
	track_pid "$STARTED_WORKLOAD_PID"
	if [ "$workload_mode" = "stress" ]; then
		(
			sleep "$seconds"
			kill "$STARTED_WORKLOAD_PID" 2>/dev/null || true
		) &
		STARTED_KILLER_PID=$!
		track_pid "$STARTED_KILLER_PID"
	fi
	set -e
}

normalize_syscall_workload_rc() {
	local rc="$1"
	local workload_mode="$2"
	if [ "$workload_mode" = "stress" ]; then
		case "$rc" in
		0|124|137|143)
			return 0
			;;
		esac
	fi
	return "$rc"
}

run_json_scenario() {
	local sc="$1"
	local seconds
	seconds="$(default_duration "$sc")"
	local workload_mode
	workload_mode="$(effective_workload_mode)"
	preflight_for_scenario "$sc" "$workload_mode"

	local dir="$OUT/$sc"
	local json="$dir/output.json"
	local stderr="$dir/ebpf-rca.stderr"
	local workload_log="$dir/workload.log"
	local summary="$dir/check.json"
	local truth="$dir/ground_truth.json"
	local truth_log="$dir/ground_truth.log"
	local truth_rc=0
	local io_file=""
	mkdir -p "$dir"
	if [ "$sc" = "io" ]; then
		io_file="${IO_PATH:-$OUT/fio-test.img}"
	fi

	log "scenario=$sc duration=${seconds}s workload=$workload_mode"
	local tool_pid=""
	local workload_pid=""
	local syscall_killer_pid=""
	local truth_pid=""

	if [ "$sc" = "idle_lock" ]; then
		log "starting workload for $sc"
		set +e
		run_workload "$sc" "$seconds" "$workload_mode" >"$workload_log" 2>&1 &
		workload_pid=$!
		track_pid "$workload_pid"
		set -e

		set_tool_args "$sc" "$seconds"
		TOOL_ARGS+=(--target-pid "$workload_pid")
		log "starting ebpf-rca: ${TOOL_ARGS[*]}"
		set +e
		run_ebpf "${TOOL_ARGS[@]}" >"$json" 2>"$stderr" &
		tool_pid=$!
		track_pid "$tool_pid"
		set -e
	elif [ "$sc" = "syscall" ]; then
		log "starting workload for $sc"
		start_syscall_workload "$seconds" "$workload_mode" "$workload_log"
		workload_pid="$STARTED_WORKLOAD_PID"
		syscall_killer_pid="$STARTED_KILLER_PID"

		log "recording ground truth for $sc root_pid=$workload_pid"
		local truth_args=(--write-truth --watch --watch-timeout "$((seconds + 5))s" --scenario "$sc" --root-pid "$workload_pid" --truth "$truth")
		set +e
		"$CHECKER" "${truth_args[@]}" >"$truth_log" 2>&1 &
		truth_pid=$!
		track_pid "$truth_pid"
		set -e

		set_tool_args "$sc" "$seconds"
		TOOL_ARGS+=(--target-pid "$workload_pid")
		log "starting ebpf-rca: ${TOOL_ARGS[*]}"
		set +e
		run_ebpf "${TOOL_ARGS[@]}" >"$json" 2>"$stderr" &
		tool_pid=$!
		track_pid "$tool_pid"
		set -e
	else
		set_tool_args "$sc" "$seconds"
		log "starting ebpf-rca: ${TOOL_ARGS[*]}"
		set +e
		run_ebpf "${TOOL_ARGS[@]}" >"$json" 2>"$stderr" &
		tool_pid=$!
		track_pid "$tool_pid"
		set -e

		sleep 2
		log "starting workload for $sc"
		set +e
		run_workload "$sc" "$seconds" "$workload_mode" >"$workload_log" 2>&1 &
		workload_pid=$!
		track_pid "$workload_pid"
		set -e

		case "$sc" in
		idle|idle_cpu|idle_io|idle_lock|idle_syscall)
			;;
		*)
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
			;;
		esac
	fi

	set +e
	wait "$workload_pid"
	local workload_rc=$?
	if [ "$sc" = "syscall" ] && normalize_syscall_workload_rc "$workload_rc" "$workload_mode"; then
		workload_rc=0
	fi
	if [ -n "$syscall_killer_pid" ]; then
		kill "$syscall_killer_pid" 2>/dev/null || true
		wait "$syscall_killer_pid" 2>/dev/null || true
	fi
	if [ -n "$truth_pid" ]; then
		wait "$truth_pid"
		truth_rc=$?
	fi
	wait "$tool_pid"
	local tool_rc=$?
	set -e

	if [ "$workload_rc" -ne 0 ]; then
		log "workload for $sc exited with $workload_rc; see $workload_log"
	fi
	if [ "$tool_rc" -ne 0 ]; then
		log "ebpf-rca for $sc exited with $tool_rc; see $stderr"
	fi
	if [ "$truth_rc" -ne 0 ]; then
		log "ground truth capture for $sc failed; see $truth_log"
		return 1
	fi

	log "validating $sc"
	local check_args=(--spec "$SPEC" --scenario "$sc" --input "$json" --summary "$summary")
	case "$sc" in
	idle|idle_cpu|idle_io|idle_lock|idle_syscall)
		;;
	*)
		check_args+=(--truth "$truth")
		;;
	esac
	set +e
	"$CHECKER" "${check_args[@]}" >"$dir/check.log" 2>&1
	local check_rc=$?
	set -e
	if [ "$check_rc" -ne 0 ]; then
		log "validation failed for $sc; see $dir/check.log"
		return 1
	fi
	if [ "$workload_rc" -ne 0 ] || [ "$tool_rc" -ne 0 ]; then
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

	start_syscall_workload "$seconds" "$workload_mode" "$dir/workload_syscall.log"
	local syscall_pid="$STARTED_WORKLOAD_PID"
	local syscall_killer_pid="$STARTED_KILLER_PID"

	set +e
	"$CHECKER" --write-truth --watch --watch-timeout "$((seconds + 5))s" --scenario syscall --root-pid "$syscall_pid" --truth "$syscall_truth" >"$syscall_truth_log" 2>&1 &
	local syscall_truth_pid=$!
	track_pid "$syscall_truth_pid"
	run_ebpf --scenario all --cpu-threshold 0.50 --syscall-rate-threshold 1000 --sustain 1 --target-pid "$syscall_pid" --report "$report" --duration "${tool_seconds}s" >"$stdout" 2>"$stderr" &
	local tool_pid=$!
	track_pid "$tool_pid"
	set -e

	sleep 2
	set +e
	run_workload cpu "$seconds" "$workload_mode" >"$dir/workload_cpu.log" 2>&1 &
	local cpu_pid=$!
	track_pid "$cpu_pid"
	"$CHECKER" --write-truth --watch --watch-timeout "$((seconds + 5))s" --scenario cpu --root-pid "$cpu_pid" --truth "$cpu_truth" >"$cpu_truth_log" 2>&1 &
	local cpu_truth_pid=$!
	track_pid "$cpu_truth_pid"
	wait "$cpu_pid"
	local cpu_rc=$?
	wait "$syscall_pid"
	local syscall_rc=$?
	if normalize_syscall_workload_rc "$syscall_rc" "$workload_mode"; then
		syscall_rc=0
	fi
	if [ -n "$syscall_killer_pid" ]; then
		kill "$syscall_killer_pid" 2>/dev/null || true
		wait "$syscall_killer_pid" 2>/dev/null || true
	fi
	wait "$cpu_truth_pid"
	local cpu_truth_rc=$?
	wait "$syscall_truth_pid"
	local syscall_truth_rc=$?
	wait "$tool_pid"
	local tool_rc=$?
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
		run_scenarios idle_cpu idle_io idle_lock idle_syscall
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
