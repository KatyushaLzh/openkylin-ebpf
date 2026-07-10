# 容器化部署（Docker / Podman）

容器运行的仍是**宿主内核**中的 eBPF：硬前提依然是 openKylin Kernel 6.6+、宿主可读 BTF、
typed BTF tracepoint 与 `fentry/fexit`。镜像不能给不满足条件的宿主补齐这些能力，也没有旧探针
降级路径。

当前实现借助 host PID namespace 做宿主级 TGID/TID 归因；它没有真实 cgroup/container 聚合，
因此不能把“容器内运行”写成“已支持按容器根因聚合”。

## 1. 构建镜像

Dockerfile 会在 builder 中重新执行 bpf2go。先用**目标宿主** BTF 生成 `bpf/vmlinux.h`：

```bash
cd ebpf-rca
make vmlinux
docker build -t ebpf-rca .       # 或 podman build -t ebpf-rca .
```

镜像架构必须与运行主机匹配。x86_64 构建成功不能证明 ARM64 可用；ARM64 应在 ARM64 openKylin
主机原生构建并完成平台验收。x86_64/arm64 使用 little-endian bpf2go 产物。

## 2. 特权模式运行

结束时保存严格 `DiagnosticSession`：

```bash
mkdir -p out
docker run --rm --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v "$PWD/out:/out" \
  ebpf-rca --scenario all --allow-partial=false --duration 60s \
  --format json --output /out/session.json

jq '{partial,collectors,reports}' out/session.json
python3 scripts/validate_report.py out/session.json
```

若宿主没有单独挂载 `/sys/kernel/tracing`，删除该 `-v`，确认 `/sys/kernel/debug/tracing` 可见。
`--format json` 只在正常退出时写出完整 session；需要实时输出时用 `--format jsonl`。

现有封装脚本使用 privileged + host PID：

```bash
bash scripts/docker_run.sh --scenario all --report /tmp/report.md --duration 60s
```

脚本把当前目录的 `out/` 挂到容器 `/tmp`，适合生成 Markdown 演示报告。

## 3. Capability 模式

不同发行版、容器 runtime、seccomp 与 LSM 策略不同，以下是常见起点，不保证比 privileged 模式
更可移植：

```bash
docker run --rm --pid=host \
  --cap-add BPF --cap-add PERFMON --cap-add SYS_ADMIN --cap-add SYS_RESOURCE \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  ebpf-rca --scenario all --allow-partial=false --duration 30s --format json
```

若 runtime 默认 seccomp/LSM 拒绝 `bpf`、`perf_event_open` 或 BPF link attach，需要调整对应 profile；
不要用 `--allow-partial` 掩盖权限问题后把结果当正式证据。

## 4. 挂载与语义

- `--pid=host`：容器 `/proc` 与内核事件中的 TGID/TID 可一致归因；
- `/sys/kernel/btf`：CO-RE relocation、typed tracepoint 和 fentry 的宿主 BTF 来源；
- tracefs/debugfs：direct-reclaim 等 tracepoint 挂载与排障；
- `/proc/kallsyms`：内核栈符号化，仍受宿主 `kptr_restrict` 限制；
- `related_object.pid` 始终是宿主 TGID，`tid` 是线程；不是容器内重映射 PID。

## 5. 失败排查与证据边界

- `attach tp_btf/...` / `fentry/do_futex`：检查宿主 Kernel 6.6+BTF 和 BTF prototype；
- `operation not permitted`：检查 capability、seccomp、LSM、no-new-privileges；
- `partial=true`：查看具体 collector error；正式测试要求默认 strict all-mode；
- 容器中 I/O 无事件：overlay/tmpfs 写入可能不经过预期块设备，fio 使用宿主真实块设备路径；
- JSON 文件为空：进程被 SIGKILL 或仍未结束；用 SIGTERM 正常收尾，实时观察使用 JSONL。

最终 x86_64/ARM64 兼容性证据应由各宿主执行 `scripts/platform_acceptance.sh` 生成 clean build、五场景
E2E、30 分钟 soak、性能与 SHA256 bundle。容器演示不能替代宿主平台验收。
