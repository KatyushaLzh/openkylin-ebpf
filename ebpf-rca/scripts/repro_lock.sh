#!/usr/bin/env bash
# 复现场景④：锁竞争。使用赛题官方 stress-ng --mutex 注入锁争用，
# 同时运行 ebpf-rca(lock) 做 off-CPU 阻塞 + 唤醒链分析并输出诊断。
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

echo "[repro] 启动 ebpf-rca 场景=lock（后台）..."
sudo "$BIN" --scenario lock --interval 1s --threshold 0.30 --sustain 3 \
	--format md --duration "${DUR}s" &
RCA_PID=$!
cleanup() {
	if kill -0 "$RCA_PID" 2>/dev/null; then
		if kill "$RCA_PID" 2>/dev/null; then :; fi
	fi
}
trap cleanup EXIT

sleep 2
echo "[repro] 注入锁竞争负载（官方脚本）..."
set +e
"$STRESS_NG" --mutex 8 --timeout "${DUR}s" --metrics-brief
WORKLOAD_RC=$?
wait "$RCA_PID" 2>/dev/null
TOOL_RC=$?
set -e

if [ "$WORKLOAD_RC" -ne 0 ] || [ "$TOOL_RC" -ne 0 ]; then
	echo "[repro] 失败：workload=$WORKLOAD_RC tool=$TOOL_RC" >&2
	exit 1
fi
echo "[repro] 完成。"
