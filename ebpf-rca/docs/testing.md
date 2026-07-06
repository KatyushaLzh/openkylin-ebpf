# 测试与复现说明

本文给出每类异常场景的注入方法、预期输入/输出与复核步骤，便于评委复现。
自动化端到端测试见 [local-testing.md](local-testing.md)，手工演示脚本见下文。
所有命令需 root 或 `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN`，内核 6.6+ 且启用 BTF。

## 0. 准备

```bash
# 先进入仓库根目录
cd ebpf-rca
make deps && make vmlinux && make build
```

`make deps` 会转调仓库根目录的 `setup_env.sh --no-build`。在 openKylin 上不要依赖
`apt-get install bpftool stress-ng` 一步成功：`bpftool` 通常只是 wrapper，`stress-ng` 可能因
`libipsec-mb0` 缺失无法安装；脚本会把可用二进制放到 `.build_deps/`。

## 1. 五类异常场景复现

每个 `repro_*.sh` 都会「启动工具 → 注入官方负载 → 自动输出诊断」。

| 场景 | 命令 | 注入负载 | 预期诊断输出 |
|---|---|---|---|
| ① CPU | `bash scripts/repro_cpu.sh 60` | `stress-ng --cpu`(官方) | anomaly_type=CPU异常占用；cpu_util≈高；根因=计算热点 |
| ② I/O | `bash scripts/repro_io.sh 60` | `fio randrw`(官方) | anomaly_type=I/O延迟抖动；含 P99/队列深度；关联块设备 |
| ③ 内存 | `bash scripts/repro_mem.sh 60` | `stress-ng --vm`(官方) | anomaly_type=内存抖动；direct_reclaim_count>0；定位肇事进程 |
| ④ 锁竞争 | `bash scripts/repro_lock.sh 60` | `stress-ng --mutex`(官方) | anomaly_type=锁竞争；阻塞栈含 futex/mutex；含唤醒链 tid |
| ⑤ syscall | `bash scripts/repro_syscall.sh 30` | `dd bs=1`(自构造) | anomaly_type=系统调用热点；syscall=read/write；calls_per_sec 高 |

### 输出校核要点
- 结构化输出含 7 字段：`anomaly_type / related_object / key_metrics / time_window / suspected_root_cause / evidence_chain / suggestion`。
- 可切换 `--format json|yaml|md` 验证三种格式；JSON 可用 `jq .` 校验可解析性。
- 证据链(`evidence_chain`)每条都可回溯到具体指标 / 调用栈 / 事件。

## 2. 误报/漏报快速核验

- 空载运行工具 60s，应**无**异常输出（验证误报率：阈值+连续窗口可抑制抖动）。
- 注入负载后应在 `sustain` 个窗口内产生对应异常（验证漏报）。
- 单场景可调 `--threshold` / `--sustain` 观察灵敏度变化；`--scenario all` 使用
  `--cpu-threshold`、`--io-p99-threshold-ms`、`--mem-avail-floor-pct`、
  `--lock-offcpu-threshold`、`--syscall-rate-threshold` 分别调参。

## 3. 性能开销基准

```bash
make bench            # 全部场景，结果写入 bench.md
# 或：bash scripts/benchmark.sh cpu
```

输出表含每场景：基线耗时、加载工具后耗时、负载变慢%、工具 CPU%、工具峰值 RSS。
判读：负载变慢% 越小越好；工具 CPU%/RSS 为 ebpf-rca 自身开销。

> 说明：syscall 场景因 `raw_syscalls` 触发极频繁，开销高于其它场景，属预期；
> 生产可经 `--target-pid` 过滤只观测目标进程以降开销。

## 4. 自动化本地 E2E

```bash
make test-smoke       # CPU + syscall 快速链路
make test-local       # 五类正向异常
make test-negative    # 空载误报检查
make test-report      # Markdown 汇总报告
make docs-check       # CLI 参数与 README 同步检查
```

每次运行会把 JSON 输出、负载日志、校验摘要写入 `test-results/<timestamp>/`。
断言规格在 `tests/scenarios.yaml`，校验器为 `cmd/rca-testcheck`。
