#!/usr/bin/env bash
# Compatibility wrapper for the strict paired benchmark.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-all}"
REQUESTED_REPORT="${2:-}"
OUT_DIR="${BENCH_OUT:-$ROOT/outputs/bench}"
DURATION="${BENCH_DURATION:-60}"
REPEAT="${BENCH_REPEAT:-5}"

bash "$ROOT/scripts/bench_overhead.sh" \
	--scenario "$SCENARIO" --duration "$DURATION" --repeat "$REPEAT" --out "$OUT_DIR"

if [ -n "$REQUESTED_REPORT" ]; then
	cp "$OUT_DIR/bench.md" "$REQUESTED_REPORT"
fi
