# 测试与复现说明

本文给出每类异常场景的注入方法、预期输入/输出与复核步骤，便于评委复现。
自动化端到端测试见 [local-testing.md](local-testing.md)，手工演示脚本见下文。
所有命令需 root 或 `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_ADMIN`，内核 6.6+ 且启用 BTF。

## 0. 准备

```bash
# 先进入仓库根目录
cd ebpf-rca
make deps && make vmlinux
make build test-checker test-load
```

`make deps` 会转调仓库根目录的 `setup_env.sh --no-build`。在 openKylin 上不要依赖
`apt-get install bpftool stress-ng` 一步成功：`bpftool` 通常只是 wrapper，`stress-ng` 可能因
`libipsec-mb0` 缺失无法安装；脚本会把可用二进制放到 `.build_deps/`。

若网络受限但依赖已经在本机 Go module cache 中，可离线构建：

```bash
export GOCACHE=/var/tmp/go-cache
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
export GOPROXY=off GOSUMDB=off
go mod download
make build test-checker test-load
```

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
> mem/lock/syscall 可经 `--target-pid` 过滤只观测目标进程树，以降低噪声和开销。

## 4. 多轮准确率评测

```bash
make accuracy-full
```

该目标复用 `scripts/test_local.sh`，默认对 CPU/I/O/mem/lock/syscall 五类正例和
`idle_cpu/idle_io/idle_lock/idle_syscall` 四类负例各跑 3 轮。输出写入
`outputs/accuracy/`，其中 `accuracy.md` 是报告摘要，`accuracy_summary.csv` 是场景级汇总，
两个 SVG 图表可直接用于技术报告。

2026-07-08 实测结果：

- 27/27 轮生成有效 `check.json`；总体诊断准确率 100.0%，端到端通过率 100.0%。
- CPU、I/O、mem、lock、syscall 正例全部命中 workload oracle。
- 四类 idle 负例全部无告警，误报率 0%。
- mem / lock / syscall 复现路径均使用 `--target-pid` 绑定 workload 进程树，避免桌面后台进程污染根因对象。
- 历史 77.8% 版本中的 mem/lock 归因失败已通过进程树过滤修复；最新口径以 `outputs/accuracy/accuracy.md` 为准。

## 5. 自动化本地 E2E

```bash
bash scripts/test_local.sh smoke --workload deterministic  # CPU + syscall 快速链路
bash scripts/test_local.sh all --workload deterministic    # 五类正向异常
bash scripts/test_local.sh negative                        # 分场景空载误报检查
bash scripts/test_local.sh report --workload deterministic # Markdown 汇总报告
make docs-check                                            # CLI 参数与 README 同步检查
```

每次运行会把 JSON 输出、负载日志、校验摘要写入 `test-results/<timestamp>/`。
断言规格在 `tests/scenarios.yaml`，校验器为 `cmd/rca-testcheck`。

自动化 E2E 的核心不是只看“是否有报告”，而是检查报告对象是否命中本次 workload：

- CPU / lock：报告对象按 tid 匹配 workload 线程集合。
- mem / syscall：报告对象按 tgid 匹配 workload 进程集合。
- I/O：报告块设备匹配测试文件所在设备；分区设备会归一到父块设备。
- report_all：同时传入 CPU 和 syscall 两份 ground truth，校验汇总报告覆盖本次 workload。

正例中未命中 workload 的额外报告会进入 `warnings/extra_reports`，默认不让测试失败，但用于暴露误报。
负例已拆成 `idle_cpu / idle_io / idle_lock / idle_syscall`，分别约束各探针空闲窗口下的误报。

## 6. 实机一键复跑

本机完整验证可直接运行：

```bash
./out/run-real-ebpf-e2e.sh
```

该 wrapper 默认 `GO_OFFLINE=1`，使用当前用户 `GOMODCACHE` 离线构建，随后以
`sudo -n /usr/bin/bash scripts/test_local.sh ... --no-build` 进入 root/eBPF 阶段。
不要用 `sudo` 直接运行整个 wrapper，否则 root 与普通用户的 Go cache 会分裂。

最近一次本机实测通过：

| 阶段 | 结果目录 |
|---|---|
| preflight + smoke | `test-results/20260707-212151` |
| lock | `test-results/20260707-212241` |
| syscall | `test-results/20260707-212316` |
| io | `test-results/20260707-212342` |
| all | `test-results/20260707-212417` |
| negative | `test-results/20260707-212712` |
| report | `test-results/20260707-212833` |
