# ebpf-rca — 基于 eBPF 的系统异常观测与根因定位工具

> 第三届中国研究生操作系统开源创新大赛 · 系统创新赛道
> 目标平台：openKylin / Kernel 6.6+，x86_64 / ARM64（鼓励 RISC-V）

低侵入、低开销地观测系统异常，并输出**带证据链的结构化根因诊断**。核心判定基于
确定性规则引擎（零幻觉、可回溯），契合赛题"降低模型幻觉错误率"的要求。

## 架构

```
 eBPF 采集层(CO-RE/libbpf)  ->  关联分析  ->  根因推断(规则引擎)  ->  结构化输出
   sched_switch/wakeup           detector        rca(evidence chain)   JSON/YAML/MD
```

| 目录 | 说明 |
|---|---|
| `ebpf-rca/bpf/cpu.bpf.c` | 场景① CPU 采集探针（sched tracepoint，内核态聚合） |
| `ebpf-rca/internal/collector` | 加载/挂载 eBPF，按窗口读取并差分 |
| `ebpf-rca/internal/detector` | 时序异常判定（持续高占用规则，可扩展 EWMA/3-sigma） |
| `ebpf-rca/internal/rca` | 确定性根因推断 + 证据链生成 |
| `ebpf-rca/internal/schema` | 统一结构化输出 schema（7 字段，含证据链） |
| `ebpf-rca/internal/output` | JSON / YAML / Markdown 渲染 |
| `ebpf-rca/cmd/ebpf-rca` | CLI 入口 |
| `ebpf-rca/scripts` | 一键部署 / 复现场景脚本 |

## 快速开始（openKylin / Kernel 6.6+）

需要 root 或 `CAP_BPF`、`CAP_PERFMON`、`CAP_SYS_ADMIN`，且内核启用 BTF
（`/sys/kernel/btf/vmlinux` 存在）。

```bash
# 0. openKylin 推荐：在仓库根目录准备 bpftool/libbpf/stress-ng 兜底依赖
# 先进入你 clone 下来的仓库根目录
bash setup_env.sh --no-build

cd ebpf-rca

# 1. 依赖（make deps 会转调 ../setup_env.sh --no-build）
make deps

# 2. 生成 vmlinux.h（CO-RE 前提）
make vmlinux

# 3. 生成 eBPF 字节码 + 编译
make build         # = go generate ./... && go build

# 4. 运行（JSON 输出）
sudo ./bin/ebpf-rca --format json

# 5. 一键复现场景①（注入 CPU 负载并观测）
bash scripts/repro_cpu.sh 60

# 6. 一键复现场景②（注入随机读写，做块层时延/队列深度分析）
sudo ./bin/ebpf-rca --scenario io --format md
bash scripts/repro_io.sh 60

# 7. 一键复现场景③（注入内存压力，做 direct reclaim / kswapd 分析）
sudo ./bin/ebpf-rca --scenario mem --format md
bash scripts/repro_mem.sh 60

# 8. 一键复现场景④（注入锁竞争，做 off-CPU + 唤醒链分析）
sudo ./bin/ebpf-rca --scenario lock --format md
bash scripts/repro_lock.sh 60

# 9. 一键复现场景⑤（注入高频 syscall，做热点定位）
sudo ./bin/ebpf-rca --scenario syscall --format md
bash scripts/repro_syscall.sh 30

# 10. 性能开销基准（全部场景，结果写入 bench.md）
make bench

# 11. 同时跑全部场景，汇总成一份 Markdown 诊断报告
sudo ./bin/ebpf-rca --scenario all --report report.md --duration 60s

# 12. 容器化运行（Docker/Podman，详见 docs/docker.md）
make vmlinux && docker build -t ebpf-rca .
bash scripts/docker_run.sh --scenario all
```

测试与复现细则见 [ebpf-rca/docs/testing.md](ebpf-rca/docs/testing.md)；本地自动化 E2E 见
[ebpf-rca/docs/local-testing.md](ebpf-rca/docs/local-testing.md)；容器部署见 [ebpf-rca/docs/docker.md](ebpf-rca/docs/docker.md)；
实测排查见 [ebpf-rca/docs/troubleshooting.md](ebpf-rca/docs/troubleshooting.md)。

openKylin 上的两个常见坑已经由 `setup_env.sh` 兜底处理：`/usr/sbin/bpftool` 可能只是
linux-tools wrapper，`stress-ng` apt 包可能因 `libipsec-mb0` 缺失无法安装。脚本会使用
`.build_deps/bpftool/src/bpftool` 和 `.build_deps/bin/stress-ng`。

场景选择见 `--scenario cpu|io|lock`。I/O 场景输出含 **IOPS / 平均·P99·最大时延 / 吞吐 /
队列深度**，关联对象为块设备；锁竞争场景输出含**阻塞栈符号**（如 `futex_wait_queue`）、
**唤醒链上游 tid**（疑似持锁方）与 off-CPU 阻塞占比，均构成可回溯的证据链。

## 命令行参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--interval` | `1s` | 采样窗口 |
| `--threshold` | `0.90` | CPU 占用阈值（单核占比） |
| `--sustain` | `3` | 连续超阈值多少窗口才触发，抑制抖动误报 |
| `--duration` | `0` | 总运行时长，0=直到 Ctrl-C |
| `--format` | `json` | `json` / `yaml` / `md` |
| `--output` | stdout | 输出文件路径 |

## 输出示例（节选）

```json
{
  "anomaly_type": "CPU异常占用",
  "related_object": { "pid": 12345, "tid": 12345, "comm": "matrixprod" },
  "key_metrics": { "cpu_util": 0.97, "ctx_switch_per_min": 120, "runq_wait_us": 8.3 },
  "time_window": { "start": "2026-07-20T10:00:01Z", "end": "2026-07-20T10:00:04Z" },
  "suspected_root_cause": "用户态计算热点导致 CPU 饱和（计算密集或异常 busy loop）",
  "confidence": 0.93,
  "evidence_chain": [
    { "type": "metric", "name": "cpu_util", "value": 0.97, "threshold": 0.9, "desc": "单核 CPU 占用率持续高于阈值" }
  ],
  "suggestion": "定位用户态热点函数，优化算法或并行度；排查是否存在异常 busy loop"
}
```

## 路线图（对应赛题 5 类场景）

- [x] ① CPU 异常占用 / 调度延迟（`--scenario cpu`）
- [x] ② I/O 延迟抖动 — 块层时延 + P99 + 队列深度 + 吞吐（`--scenario io`）
- [x] ③ 内存抖动 / OOM — direct reclaim + kswapd + 缺页 + 可用内存（`--scenario mem`）
- [x] ④ 锁竞争 — off-CPU 阻塞 + 唤醒链 + 阻塞栈符号化（`--scenario lock`）
- [x] ⑤ 系统调用热点 — 高频/高耗时分类，raw_syscalls 直方（`--scenario syscall`）
- [x] 性能开销 benchmark（工具加载前后对比，`make bench`）
- [x] 自动诊断报告（`--report`，多场景汇总 Markdown）+ `--scenario all`
- [x] 容器化部署（Docker / Podman，见 [ebpf-rca/docs/docker.md](ebpf-rca/docs/docker.md)）
- [ ] 多架构实测 / RISC-V 适配

## 已知限制

- `pid` 字段为内核线程 id(tid)；进程级聚合(tgid)待补（可经 `bpf_get_current_task` 或 `/proc`）。
- 热点函数(stack)证据为扩展项，将通过 `perf_event` 采样补充。
- CPU 占用率以"单核占比"表示，1.0 ≈ 占满一个核。

## 许可证

eBPF 程序以 GPL 协议加载（内核要求）；用户态代码许可证见 `LICENSE`。
