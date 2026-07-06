#!/usr/bin/env bash
# 一键部署：安装依赖、生成字节码、编译二进制。在 openKylin (Kernel 6.6+) 上执行。
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[deploy] 安装构建依赖..."
make deps

echo "[deploy] 生成 vmlinux.h..."
make vmlinux

echo "[deploy] 编译..."
make build

echo "[deploy] 完成，二进制位于 bin/ebpf-rca"
echo "运行示例： sudo ./bin/ebpf-rca --format json"
