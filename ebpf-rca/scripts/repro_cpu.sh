#!/usr/bin/env bash
# 复现场景①：CPU 异常占用。使用赛题官方给定的 stress-ng 脚本注入负载，
# 同时运行 ebpf-rca 观测并输出诊断结果。
set -euo pipefail

DUR="${1:-60}"
BIN="$(dirname "$0")/../bin/ebpf-rca"
STRESS_NG="${STRESS_NG:-$(dirname "$0")/../../.build_deps/bin/stress-ng}"

if [ ! -x "$STRESS_NG" ] && command -v stress-ng >/dev/null 2>&1; then
	STRESS_NG="$(command -v stress-ng)"
fi

if [ ! -x "$STRESS_NG" ]; then
	echo "请先安装 stress-ng（make deps 或 apt-get install stress-ng）" >&2
	exit 1
fi

echo "[repro] 启动 ebpf-rca（后台）..."
sudo "$BIN" --interval 1s --threshold 0.90 --sustain 3 --format md --duration "${DUR}s" &
RCA_PID=$!

sleep 2
echo "[repro] 注入 CPU 负载（官方脚本）..."
"$STRESS_NG" --cpu 4 --cpu-method matrixprod --timeout "${DUR}s" --metrics-brief || true

wait "$RCA_PID" 2>/dev/null || true
echo "[repro] 完成。"
