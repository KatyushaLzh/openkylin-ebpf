#!/usr/bin/env bash
# 复现场景⑤：系统调用热点（赛题未提供官方脚本，此处自构造）。
# 用 dd 以 1 字节块读写制造海量 read/write syscall（高频热点）；
# 同时运行 ebpf-rca(syscall) 观测并输出 Top syscall 诊断。
set -euo pipefail

DUR="${1:-30}"
BIN="$(dirname "$0")/../bin/ebpf-rca"

echo "[repro] 启动 ebpf-rca 场景=syscall（后台）..."
sudo "$BIN" --scenario syscall --interval 1s --threshold 10000 --sustain 2 \
	--format md --duration "${DUR}s" &
RCA_PID=$!

sleep 2
echo "[repro] 注入高频系统调用负载（dd 1字节块读写）..."
# bs=1 使每次仅搬运 1 字节 -> 海量 read/write syscall
timeout "${DUR}s" dd if=/dev/zero of=/dev/null bs=1 count=200000000 2>/dev/null || true

wait "$RCA_PID" 2>/dev/null || true
echo "[repro] 完成。"
