#!/usr/bin/env bash
# Lightweight documentation drift checks for CLI flags and referenced files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -z "${GOCACHE:-}" ]; then
	home_cache="${HOME:-}/.cache/go-build"
	if [ -z "${HOME:-}" ] || [ ! -d "$home_cache" ] || [ ! -w "$home_cache" ]; then
		export GOCACHE="${TMPDIR:-/var/tmp}/go-cache"
		mkdir -p "$GOCACHE"
	fi
fi

help_text="$(go run ./cmd/ebpf-rca --help 2>&1 || true)"
required_flags=(
	--scenario
	--interval
	--threshold
	--cpu-threshold
	--io-p99-threshold-ms
	--mem-avail-floor-pct
	--lock-offcpu-threshold
	--syscall-rate-threshold
	--target-pid
	--report
)

for flag in "${required_flags[@]}"; do
	help_flag="-${flag#--}"
	if ! grep -q -- "$help_flag" <<<"$help_text"; then
		echo "missing flag in --help: $flag" >&2
		exit 1
	fi
	if ! grep -q -- "$flag" README.md; then
		echo "missing flag in README.md: $flag" >&2
		exit 1
	fi
done

for path in docs/design.md docs/testing.md docs/troubleshooting.md docs/docker.md tests/scenarios.yaml; do
	if [ ! -f "$path" ]; then
		echo "documented path missing: $path" >&2
		exit 1
	fi
done

echo "docs check passed"
