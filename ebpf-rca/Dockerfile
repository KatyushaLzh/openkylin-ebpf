# 多阶段构建：builder 编译 eBPF 字节码与二进制，runtime 仅含运行所需。
#
# 构建前提：先在目标主机(openKylin)执行 `make vmlinux` 生成 bpf/vmlinux.h，
# 使其进入构建上下文（CO-RE 编译需要）。然后：
#   docker build -t ebpf-rca .
# 运行（需特权与主机命名空间，见 docs/docker.md / scripts/docker_run.sh）：
#   docker run --rm -it --privileged --pid=host \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro -v /sys/kernel/debug:/sys/kernel/debug \
#     ebpf-rca --scenario all --report /tmp/report.md

FROM golang:1.22-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev make && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# 生成 eBPF 字节码(需 bpf/vmlinux.h 已在上下文中) 并编译
RUN go generate ./... && \
    CGO_ENABLED=0 go build -buildvcs=false -o /out/ebpf-rca ./cmd/ebpf-rca

FROM debian:bookworm-slim
# stress-ng / fio 便于在容器内直接复现场景（可按需精简）
RUN apt-get update && apt-get install -y --no-install-recommends \
        stress-ng fio && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/ebpf-rca /usr/local/bin/ebpf-rca
ENTRYPOINT ["/usr/local/bin/ebpf-rca"]
CMD ["--scenario", "all", "--report", "/tmp/report.md", "--duration", "60s"]
