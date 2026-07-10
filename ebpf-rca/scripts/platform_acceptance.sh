#!/usr/bin/env bash
# Produce one self-contained openKylin platform acceptance bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GIT_TOP="$(git -C "$ROOT" rev-parse --show-toplevel)"
ROOT_PREFIX="$(git -C "$ROOT" rev-parse --show-prefix)"
ROOT_PREFIX="${ROOT_PREFIX%/}"
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
OUT=""
SOAK_DURATION="30m"
ACCURACY_REPEAT=10
BENCH_REPEAT=5
BENCH_DURATION=60
E2E_DURATION=30
CLEAN_TMP=""

usage() {
	printf '%s\n' \
		"Usage: bash scripts/platform_acceptance.sh [options]" \
		"  --out DIR                 evidence directory" \
		"  --soak-duration DURATION  default/minimum: 30m (integer s|m|h)" \
		"  --accuracy-repeat N       default/minimum: 10" \
		"  --bench-repeat N          default/minimum: 5" \
		"  --bench-duration SECONDS  default/minimum: 60" \
		"  --e2e-duration SECONDS    default/minimum: 30"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--out) OUT="${2:-}"; shift 2 ;;
	--soak-duration) SOAK_DURATION="${2:-}"; shift 2 ;;
	--accuracy-repeat) ACCURACY_REPEAT="${2:-}"; shift 2 ;;
	--bench-repeat) BENCH_REPEAT="${2:-}"; shift 2 ;;
	--bench-duration) BENCH_DURATION="${2:-}"; shift 2 ;;
	--e2e-duration) E2E_DURATION="${2:-}"; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
	esac
done

case "$ACCURACY_REPEAT:$BENCH_REPEAT:$BENCH_DURATION:$E2E_DURATION" in
*[!0-9:]*|0:*|*:0:*|*:*:0:*|*:*:*:0)
	printf 'repeat counts and durations must be positive integers\n' >&2
	exit 2
	;;
esac

duration_seconds() {
	local raw="$1" value unit multiplier
	if [[ ! "$raw" =~ ^([0-9]{1,9})([smh])$ ]]; then
		return 1
	fi
	value="${BASH_REMATCH[1]}"
	unit="${BASH_REMATCH[2]}"
	case "$unit" in
	s) multiplier=1 ;;
	m) multiplier=60 ;;
	h) multiplier=3600 ;;
	esac
	printf '%d\n' "$((10#$value * multiplier))"
}

SOAK_SECONDS="$(duration_seconds "$SOAK_DURATION")" || {
	printf 'soak duration must be an integer with s, m, or h suffix: %s\n' "$SOAK_DURATION" >&2
	exit 2
}
if [ "$SOAK_SECONDS" -lt 1800 ] || [ "$ACCURACY_REPEAT" -lt 10 ] ||
	[ "$BENCH_REPEAT" -lt 5 ] || [ "$BENCH_DURATION" -lt 60 ] || [ "$E2E_DURATION" -lt 30 ]; then
	printf 'formal minimums: soak>=30m accuracy-repeat>=10 bench-repeat>=5 bench-duration>=60 e2e-duration>=30\n' >&2
	exit 2
fi

ARCH="$(uname -m)"
OUT="${OUT:-$ROOT/outputs/platform/${ARCH}-$(date -u +%Y%m%dT%H%M%SZ)}"
case "$OUT" in
/*) ;;
*) OUT="$PWD/$OUT" ;;
esac

# The formal run is tied to HEAD.  Historical runtime output is deliberately
# excluded, but source/config changes must be committed so the clean-checkout
# proof and the subsequently exercised code are the same revision.
SOURCE_STATUS="$(git -C "$GIT_TOP" status --porcelain --untracked-files=all -- \
	"$ROOT_PREFIX" ":(exclude)$ROOT_PREFIX/outputs/**")"
if [ -n "$SOURCE_STATUS" ]; then
	printf 'refusing formal acceptance with uncommitted project source changes:\n%s\n' "$SOURCE_STATUS" >&2
	exit 1
fi

if [ -e "$OUT" ] && [ -n "$(find "$OUT" -mindepth 1 -print -quit 2>/dev/null)" ]; then
	printf 'refusing to overwrite non-empty evidence directory: %s\n' "$OUT" >&2
	exit 1
fi
mkdir -p "$OUT" "$OUT/logs" "$OUT/e2e" "$OUT/soak" "$OUT/accuracy" "$OUT/bench" "$OUT/validation"
COMMANDS="$OUT/commands.log"
: >"$COMMANDS"

cleanup() {
	if [ -n "$CLEAN_TMP" ] && [ -d "$CLEAN_TMP" ]; then
		rm -rf "$CLEAN_TMP"
	fi
}
trap cleanup EXIT

record_command() {
	printf '[%s]' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$COMMANDS"
	printf ' %q' "$@" >>"$COMMANDS"
	printf '\n' >>"$COMMANDS"
}

run_logged() {
	local label="$1"
	shift
	record_command "$@"
	"$@" 2>&1 | tee "$OUT/logs/${label}.log"
}

record_command_in() {
	local directory="$1"
	shift
	printf '[%s] cwd=%q' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$directory" >>"$COMMANDS"
	printf ' %q' "$@" >>"$COMMANDS"
	printf '\n' >>"$COMMANDS"
}

run_logged_in() {
	local label="$1"
	local directory="$2"
	shift 2
	record_command_in "$directory" "$@"
	(cd "$directory" && "$@") 2>&1 | tee "$OUT/logs/${label}.log"
}

generated_manifest() {
	local tree="$1"
	local destination="$2"
	local name suffix file hash
	: >"$destination"
	for name in cpu lock block mem syscall; do
		for suffix in bpfel.go bpfel.o; do
			file="internal/collector/${name}_${suffix}"
			test -s "$tree/$file"
			hash="$(sha256sum "$tree/$file" | awk '{print $1}')"
			printf '%s  %s\n' "$hash" "$file" >>"$destination"
		done
	done
}

assert_formal_platform() {
	local os_id="" os_name="" kernel_release kernel_base kernel_major kernel_minor ok=0
	if [ -r /etc/os-release ]; then
		os_id="$(. /etc/os-release; printf '%s' "${ID:-}")"
		os_name="$(. /etc/os-release; printf '%s' "${NAME:-}")"
	fi
	kernel_release="$(uname -r)"
	kernel_base="${kernel_release%%-*}"
	IFS=. read -r kernel_major kernel_minor _ <<<"$kernel_base"

	printf 'os_id=%s\n' "$os_id"
	printf 'os_name=%s\n' "$os_name"
	printf 'kernel_release=%s\n' "$kernel_release"
	printf 'arch=%s\n' "$ARCH"
	printf 'btf=/sys/kernel/btf/vmlinux\n'

	if [ "${os_id,,}" != "openkylin" ] && [[ "${os_name,,}" != *openkylin* ]]; then
		printf 'ERROR: formal evidence requires openKylin, got ID=%q NAME=%q\n' "$os_id" "$os_name" >&2
		ok=1
	fi
	if ! [[ "$kernel_major" =~ ^[0-9]+$ && "$kernel_minor" =~ ^[0-9]+$ ]] || \
		! ((kernel_major > 6 || (kernel_major == 6 && kernel_minor >= 6))); then
		printf 'ERROR: formal evidence requires Kernel >= 6.6, got %q\n' "$kernel_release" >&2
		ok=1
	fi
	case "$ARCH" in
	x86_64|aarch64|arm64) ;;
	*)
		printf 'ERROR: formal evidence requires x86_64 or ARM64, got %q\n' "$ARCH" >&2
		ok=1
		;;
	esac
	if [ ! -r /sys/kernel/btf/vmlinux ] || [ ! -s /sys/kernel/btf/vmlinux ]; then
		printf 'ERROR: formal evidence requires readable, non-empty /sys/kernel/btf/vmlinux\n' >&2
		ok=1
	fi
	if ! "${SUDO[@]}" awk '$1 != "0000000000000000" && $1 != "00000000" { found=1; exit } END { exit !found }' /proc/kallsyms; then
		printf 'ERROR: formal lock classification requires readable non-zero /proc/kallsyms\n' >&2
		ok=1
	fi
	if [ "$ok" -eq 0 ]; then
		printf 'result=PASS\n'
	else
		printf 'result=FAIL\n'
	fi
	return "$ok"
}

capture_environment() {
	{
		printf 'captured_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		printf 'arch=%s\n' "$ARCH"
		uname -a
		if [ -r /etc/os-release ]; then
			printf '\n[/etc/os-release]\n'
			sed -n '1,120p' /etc/os-release
		fi
		printf '\n[toolchain]\n'
		go version
		clang --version | sed -n '1,3p'
		bpftool version
		printf '\n[BTF]\n'
		stat /sys/kernel/btf/vmlinux
		sha256sum /sys/kernel/btf/vmlinux
		printf '\n[git]\n'
		printf 'source_commit=%s\n' "$SOURCE_COMMIT"
		printf 'source_subtree=%s\n' "$ROOT_PREFIX"
		printf 'source_status_excluding_outputs=%s\n' "${SOURCE_STATUS:-clean}"
	} >"$OUT/environment.txt"
}

cd "$ROOT"
SUDO=()
if [ "$(id -u)" -ne 0 ]; then
	command -v sudo >/dev/null
	sudo -n true
	SUDO=(sudo -n)
fi
if ! assert_formal_platform 2>&1 | tee "$OUT/platform_check.txt"; then
	exit 1
fi
capture_environment

# First prove the exact committed snapshot builds and tests with only its
# checked-in bpf2go outputs.  No vmlinux generation or bpf2go invocation is
# allowed in this phase.
CLEAN_TMP="$(mktemp -d "${TMPDIR:-/var/tmp}/ebpf-rca-acceptance.XXXXXX")"
CLEAN_ARCHIVE="$OUT/validation/source-${SOURCE_COMMIT}.tar"
CLEAN_TREE_PARENT="$CLEAN_TMP/tree"
CLEAN_ROOT="$CLEAN_TREE_PARENT/$ROOT_PREFIX"
REGEN_TREE_PARENT="$CLEAN_TMP/regenerated"
REGEN_ROOT="$REGEN_TREE_PARENT/$ROOT_PREFIX"
CLEAN_GOCACHE="$CLEAN_TMP/go-cache"
mkdir -p "$CLEAN_TREE_PARENT" "$REGEN_TREE_PARENT" "$CLEAN_GOCACHE"
run_logged clean_checkout_archive git -C "$GIT_TOP" archive \
	--format=tar --output="$CLEAN_ARCHIVE" "$SOURCE_COMMIT" -- \
	"$ROOT_PREFIX" ":(exclude)$ROOT_PREFIX/outputs/**"
(
	cd "$OUT/validation"
	sha256sum "$(basename "$CLEAN_ARCHIVE")"
) >"$OUT/validation/source_archive.sha256"
run_logged clean_checkout_extract tar -xf "$CLEAN_ARCHIVE" -C "$CLEAN_TREE_PARENT"
run_logged_in clean_checkout_clean "$CLEAN_ROOT" env GOCACHE="$CLEAN_GOCACHE" make clean
run_logged_in clean_checkout_verify_generated "$CLEAN_ROOT" env GOCACHE="$CLEAN_GOCACHE" make verify-generated
generated_manifest "$CLEAN_ROOT" "$OUT/validation/generated_checked_in.sha256"
run_logged_in clean_checkout_unit "$CLEAN_ROOT" env GOCACHE="$CLEAN_GOCACHE" go test ./...
run_logged_in clean_checkout_build "$CLEAN_ROOT" env GOCACHE="$CLEAN_GOCACHE" \
	make build test-checker test-load
generated_manifest "$CLEAN_ROOT" "$OUT/validation/generated_clean_after_build.sha256"
if ! diff -u "$OUT/validation/generated_checked_in.sha256" \
	"$OUT/validation/generated_clean_after_build.sha256" \
	>"$OUT/validation/generated_clean_build.diff"; then
	printf 'clean build mutated the checked-in bpf2go artifacts\n' >&2
	cat "$OUT/validation/generated_clean_build.diff" >&2
	exit 1
fi

# Only after the checked-in artifact proof, extract the same commit a second
# time and regenerate there against this host.  CO-RE local BTF can legitimately
# vary by kernel/config/architecture, so drift is recorded as provenance rather
# than treated as a failed acceptance.  The working tree is never regenerated.
run_logged regenerated_checkout_extract tar -xf "$CLEAN_ARCHIVE" -C "$REGEN_TREE_PARENT"
run_logged_in host_vmlinux "$REGEN_ROOT" make vmlinux
run_logged_in host_generate "$REGEN_ROOT" env GOCACHE="$CLEAN_GOCACHE" make generate
generated_manifest "$REGEN_ROOT" "$OUT/validation/generated_host.sha256"

hash_diff_status=0
if diff -u "$OUT/validation/generated_checked_in.sha256" \
	"$OUT/validation/generated_host.sha256" >"$OUT/validation/generated_hashes.diff"; then
	hash_diff_status=0
else
	hash_diff_status=$?
	if [ "$hash_diff_status" -gt 1 ]; then
		printf 'failed to compare generated artifact hashes\n' >&2
		exit "$hash_diff_status"
	fi
fi

artifact_diff_status=0
record_command git diff --no-index --binary -- \
	"$CLEAN_ROOT/internal/collector" "$REGEN_ROOT/internal/collector"
if git diff --no-index --binary -- \
	"$CLEAN_ROOT/internal/collector" "$REGEN_ROOT/internal/collector" \
	>"$OUT/validation/generated_artifacts.diff"; then
	artifact_diff_status=0
else
	artifact_diff_status=$?
	if [ "$artifact_diff_status" -gt 1 ]; then
		printf 'failed to diff checked-in and host-regenerated artifacts\n' >&2
		exit "$artifact_diff_status"
	fi
fi

generated_equal=false
if [ "$hash_diff_status" -eq 0 ] && [ "$artifact_diff_status" -eq 0 ]; then
	generated_equal=true
fi
printf 'checked_in_equals_host_regenerated=%s\n' "$generated_equal" \
	>"$OUT/validation/generated_comparison.txt"

# The regenerated copy must still compile and pass unit tests, independently of
# whether its bytes equal the canonical checked-in CO-RE artifacts.
run_logged_in regenerated_unit "$REGEN_ROOT" env GOCACHE="$CLEAN_GOCACHE" go test ./...
run_logged_in regenerated_build "$REGEN_ROOT" env GOCACHE="$CLEAN_GOCACHE" \
	make build test-checker test-load

# Five positive scenarios run from the first clean tree, retaining stdout,
# stderr, truth and checker output.  This proves the checked-in CO-RE artifacts,
# not a host-mutated working tree, are the artifacts actually accepted.
run_logged_in e2e "$CLEAN_ROOT" bash scripts/test_local.sh all \
	--duration "$E2E_DURATION" --workload deterministic --no-build --out "$OUT/e2e"

# A long all-mode run must initialize every requested collector and emit one
# strict DiagnosticSession JSON document even when reports[] is empty.
run_logged_in soak "$CLEAN_ROOT" "${SUDO[@]}" ./bin/ebpf-rca \
	--scenario all --allow-partial=false --duration "$SOAK_DURATION" \
	--format json --output "$OUT/soak/session.json"
run_logged_in validate_soak "$CLEAN_ROOT" python3 scripts/validate_report.py \
	"$OUT/soak/session.json"
cp "$CLEAN_ROOT/outputs/validation/schema_check.csv" "$OUT/validation/soak_schema_check.csv"
cp "$CLEAN_ROOT/outputs/validation/schema_check.md" "$OUT/validation/soak_schema_check.md"

# Accuracy uses deterministic independent-oracle workloads, product defaults,
# and --scenario all. Performance alternates baseline/tool order inside the benchmark.
run_logged_in accuracy "$CLEAN_ROOT" python3 scripts/eval_accuracy.py \
	--scenario all --repeat "$ACCURACY_REPEAT" --workload deterministic \
	--out "$OUT/accuracy" --no-build --require-acceptance
run_logged_in benchmark "$CLEAN_ROOT" bash scripts/bench_overhead.sh \
	--scenario all --duration "$BENCH_DURATION" --repeat "$BENCH_REPEAT" --out "$OUT/bench"

(
	cd "$OUT"
	find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) >"$OUT/SHA256SUMS"
(cd "$OUT" && sha256sum -c SHA256SUMS)
printf 'platform evidence complete: %s\n' "$OUT"
