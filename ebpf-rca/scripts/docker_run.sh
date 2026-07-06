#!/usr/bin/env bash
# 在容器中运行 ebpf-rca（Docker 或 Podman 均可）。
# 需特权 + 主机 PID 命名空间 + 挂载 BTF/调试文件系统，以加载 eBPF 与观测全机。
set -euo pipefail

ENGINE="docker"
command -v docker >/dev/null 2>&1 || ENGINE="podman"
command -v "$ENGINE" >/dev/null 2>&1 || { echo "未找到 docker 或 podman" >&2; exit 1; }

IMAGE="${IMAGE:-ebpf-rca}"
# 透传用户参数；默认跑 all 场景并生成报告到容器内 /tmp/report.md
ARGS=("$@")
[ ${#ARGS[@]} -eq 0 ] && ARGS=(--scenario all --report /tmp/report.md --duration 60s)

echo "[docker_run] 使用 $ENGINE 运行镜像 $IMAGE ..."
exec "$ENGINE" run --rm -it \
	--privileged \
	--pid=host \
	-v /sys/kernel/btf:/sys/kernel/btf:ro \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v "$(pwd)/out:/tmp" \
	"$IMAGE" "${ARGS[@]}"
