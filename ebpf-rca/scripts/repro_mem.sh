#!/usr/bin/env bash
# 复现场景③：内存抖动 / 回收压力。使用赛题官方 stress-ng --vm 注入内存压力，
# 同时运行 ebpf-rca(mem) 做 direct reclaim / kswapd / 缺页分析并输出诊断。
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

echo "[repro] 启动 ebpf-rca 场景=mem（后台）..."
sudo "$BIN" --scenario mem --interval 1s --threshold 15 --sustain 3 \
	--format md --duration "${DUR}s" &
RCA_PID=$!

sleep 2
echo "[repro] 注入内存压力（官方脚本）..."
"$STRESS_NG" --vm 4 --vm-bytes 80% --vm-keep --timeout "${DUR}s" --metrics-brief || true

wait "$RCA_PID" 2>/dev/null || true
echo "[repro] 完成。"
