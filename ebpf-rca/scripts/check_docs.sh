#!/usr/bin/env bash
# Lightweight documentation drift checks for CLI flags and referenced files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -z "${GOCACHE:-}" ]; then
	export GOCACHE="$ROOT/../.go-cache"
	mkdir -p "$GOCACHE"
fi

help_text="$(go run ./cmd/ebpf-rca --help 2>&1)"
required_flags=(
	--scenario
	--interval
	--duration
	--format
	--output
	--threshold
	--cpu-threshold
	--io-p99-threshold-ms
	--mem-avail-floor-pct
	--lock-offcpu-threshold
	--lock-include-blocking
	--lock-topn
	--syscall-rate-threshold
	--target-pid
	--allow-partial
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

for path in ../README.md ../SETUP.md docs/design.md docs/testing.md docs/troubleshooting.md docs/docker.md tests/scenarios.yaml; do
	if [ ! -f "$path" ]; then
		echo "documented path missing: $path" >&2
		exit 1
	fi
done

if ! grep -q 'DiagnosticSession' ../SETUP.md || ! grep -q -- '--format jsonl' ../SETUP.md; then
	echo "SETUP.md must distinguish final JSON sessions from realtime JSONL" >&2
	exit 1
fi
for collector in cpu io mem lock syscall; do
	if ! grep -Eq "\"name\": \"$collector\".*\"health\"" README.md; then
		echo "README DiagnosticSession example lacks health for $collector" >&2
		exit 1
	fi
done

if ! awk 'BEGIN{inside=0} /^```json$/{if (!inside) {inside=1; next}} inside && /^```$/{exit} inside{print}' README.md |
	python3 -m json.tool >/dev/null; then
	echo "README DiagnosticSession example is not valid JSON" >&2
	exit 1
fi

echo "docs check passed"
