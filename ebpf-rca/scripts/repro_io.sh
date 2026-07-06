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

sleep 2
echo "[repro] 注入随机读写负载（官方 fio 脚本）..."
fio --name=randrw-test --filename="${IO_PATH}" --size=4G --rw=randrw \
	--rwmixread=70 --bs=4k --iodepth=64 --numjobs=4 --runtime="${DUR}" \
	--time_based --group_reporting || true

rm -f "${IO_PATH}"
wait "$RCA_PID" 2>/dev/null || true
echo "[repro] 完成。"
