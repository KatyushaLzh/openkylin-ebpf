# 容器化部署（Docker / Podman）

容器内运行 eBPF 工具需要：特权或 BPF 相关能力、访问主机内核 BTF 与调试文件系统、
以及主机 PID 命名空间（用于按进程归因、观测全机）。这与赛题"容器场景观测"鼓励项一致。

## 1. 构建镜像

CO-RE 编译需要 `bpf/vmlinux.h` 进入构建上下文。先在目标主机(openKylin)生成：

```bash
make vmlinux          # 生成 bpf/vmlinux.h（需 bpftool 与内核 BTF）
docker build -t ebpf-rca .      # 或： podman build -t ebpf-rca .
```

> 构建阶段会在镜像内执行 `go generate`（用 clang 编译 .bpf.c）+ `go build`。

## 2. 运行

最简（特权模式，便于演示）：

```bash
docker run --rm -it --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v "$PWD/out:/tmp" \
  ebpf-rca --scenario all --report /tmp/report.md --duration 60s
```

或用封装脚本（自动选择 docker/podman）：

```bash
mkdir -p out
bash scripts/docker_run.sh --scenario lock --format md
bash scripts/docker_run.sh                       # 默认 all + 生成报告到 out/report.md
```

## 3. 最小权限运行（替代 --privileged）

```bash
docker run --rm -it \
  --cap-add SYS_ADMIN --cap-add BPF --cap-add PERFMON \
  --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  ebpf-rca --scenario cpu
```

## 4. 说明与排查

- `--pid=host`：使容器内看到的 pid 与主机一致，保证进程/线程归因正确。
- 挂载 `/sys/kernel/btf`：CO-RE 运行时按主机内核 BTF 校验/重定位。
- 挂载 `/sys/kernel/debug`（含 tracefs）：libbpf 挂载 tracepoint 所需。
- Podman 用法与 Docker 相同（rootful 或具备相应能力）。
- 若加载失败报权限/BTF 错误：确认内核启用 `CONFIG_DEBUG_INFO_BTF`，并以特权或上述能力运行。
