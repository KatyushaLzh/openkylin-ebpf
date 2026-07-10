#!/usr/bin/env bash
# 复现场景②：I/O 延迟抖动。使用赛题官方 fio 脚本注入随机读写压力，
# 同时运行 ebpf-rca(io) 做块层时延/队列深度分析并输出诊断。
set -euo pipefail

DUR="${1:-60}"
BIN="$(dirname "$0")/../bin/ebpf-rca"
# 注意：fio 文件必须落在真实磁盘上；若 /tmp 是 tmpfs 则不产生块层 I/O。
# 可用 IO_PATH 覆盖到磁盘路径。
IO_PATH="${IO_PATH:-./fio-test.img}"

if ! command -v fio >/dev/null 2>&1; then
	echo "请先安装 fio（make deps 或 apt-get install fio）" >&2
	exit 1
fi

echo "[repro] 启动 ebpf-rca 场景=io（后台）..."
sudo "$BIN" --scenario io --interval 1s --threshold 20 --sustain 3 \
	--format md --duration "${DUR}s" &
RCA_PID=$!
cleanup() {
	if kill -0 "$RCA_PID" 2>/dev/null; then
		if kill "$RCA_PID" 2>/dev/null; then :; fi
	fi
	if rm -f "$IO_PATH" 2>/dev/null; then :; fi
}
trap cleanup EXIT

sleep 2
echo "[repro] 注入随机读写负载（官方 fio 脚本）..."
set +e
fio --name=randrw-test --filename="${IO_PATH}" --size=4G --rw=randrw \
	--rwmixread=70 --bs=4k --direct=1 --ioengine=libaio --iodepth=64 --numjobs=4 \
	--runtime="${DUR}" --time_based --group_reporting --output-format=json
WORKLOAD_RC=$?

rm -f "${IO_PATH}"
wait "$RCA_PID" 2>/dev/null
TOOL_RC=$?
set -e
if [ "$WORKLOAD_RC" -ne 0 ] || [ "$TOOL_RC" -ne 0 ]; then
	echo "[repro] 失败：workload=$WORKLOAD_RC tool=$TOOL_RC" >&2
	exit 1
fi
echo "[repro] 完成。"
