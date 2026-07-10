# 测试与复现说明

本文件区分“功能演示”和“评分证据”。单场景脚本可用于调试探针，但准确率结论只能来自
`--scenario all`、产品默认阈值、无 `--target-pid` 的严格 oracle 测试。

## 0. 环境与构建

运行硬前提：openKylin、Kernel 6.6+、可读 `/sys/kernel/btf/vmlinux`，内核支持 typed BTF
tracepoint 和 `fentry/fexit`。缺少这些能力时应失败，不存在旧 tracepoint 降级模式。

```bash
cd ebpf-rca
make deps
make vmlinux generate
make clean
go test ./...
make build test-checker test-load
```

加载需要 root，或等价的 `CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN`。先运行：

```bash
sudo -n bash scripts/env_check.sh
sudo -n ./bin/ebpf-rca --scenario all --allow-partial=false \
  --duration 10s --format json --output /tmp/ebpf-rca-session.json
python3 scripts/validate_report.py /tmp/ebpf-rca-session.json
```

合法 JSON 即使没有异常也必须是一个 `DiagnosticSession`，其中包含五个 collector 的状态和
`reports: []`，不能以空文件代替。

## 1. 输出接口校验

```bash
# 结束时输出一个严格会话 envelope
sudo -n ./bin/ebpf-rca --scenario all --duration 30s --format json

# 实时消费：每行一个紧凑 AnomalyReport
sudo -n ./bin/ebpf-rca --scenario all --duration 30s --format jsonl

# 人工阅读；--report 优先生成 Markdown 汇总
sudo -n ./bin/ebpf-rca --scenario all --duration 30s --report report.md
```

校验时同时检查：

- `DiagnosticSession.environment/configuration/collectors/partial/reports` 完整；
- 每个 report 包含比赛七个核心字段，并额外包含 `root_cause_code` 与 `confidence`；
- `related_object.pid` 是 TGID，`tid` 是线程，系统级报告有 `scope=system`；
- `time_window.elapsed_ms` 与 `start/end` 一致；
- `root_cause_code` 属于 schema 枚举，证据链不为空；
- collector 失败不会被当作零报告成功；默认 all-mode 任一初始化/Poll 失败均返回非零。

仅在故障排查时使用 `--allow-partial`。它只适用于 `--scenario all`，产物必须
`partial=true` 并保留失败 collector 的 `error`；这种运行不能进入准确率或性能主结果。

## 2. 五类功能复现

手工演示脚本仍可快速验证单条链路：

| 场景 | 命令 | 主要 oracle | 期望根因代码 |
|---|---|---|---|
| CPU | `bash scripts/repro_cpu.sh 60` | workload TGID/TID | `cpu.compute_hotspot` 或有运行队列证据时 `cpu.scheduler_pressure` |
| I/O | `bash scripts/repro_io.sh 60` | workload 所在块设备 | `io.queue_congestion` 或 `io.device_latency` |
| 内存 | `bash scripts/repro_mem.sh 60` | workload TGID；否则 system scope | `mem.reclaim_pressure` / `mem.oom_victim` |
| futex | `bin/rca-testload lock --threads 8 --duration 30s` | 显式共享 futex word 的 `uaddr`、workload TGID/TID，且 waiter>=2 | `lock.futex_contention` |
| syscall | `bin/rca-testload syscall --rate 30000 --duration 20s` | workload TGID 与 syscall 名/号；CPU 不越过 0.9 核 | `syscall.high_frequency` / `syscall.high_latency` |

这些脚本可以为演示调低阈值或指定 target，因此只证明链路能工作，不是准确率证据。复现产物仍应
通过严格 schema 校验；不得以“文件非空”作为 PASS。

## 3. 准确率主测试

```bash
make accuracy-full
# 等价核心入口：
python3 scripts/eval_accuracy.py --scenario all --repeat 10 --out outputs/accuracy --require-acceptance
```

正式产物必须检查 `outputs/accuracy/accuracy_summary.json` 中
`acceptance.coverage_complete=true` 且 `acceptance.all_targets_met=true`；脚本仅生成汇总不等于指标
自动达标。

每轮只注入一个独立 workload。正式默认选择 `--workload deterministic`：CPU、mem、lock、syscall
使用能输出独立 oracle 且避免跨标签的 `rca-testload`，I/O 仍使用 fio；`--workload stress` 只作为
附加现实压力回归，不能替代主矩阵。工具统一使用：

```text
--scenario all --allow-partial=false
产品默认阈值和默认 sustain
不传 --target-pid
```

正例覆盖 CPU、I/O、内存、futex、syscall，每类不少于 10 轮。默认负例为 `idle`、
`normal_mem`（正常大内存申请）、`normal_epoll`、`normal_io_sleep`、`normal_io_seq`（低延迟顺序
I/O），每类不少于 10 轮。I/O 压测使用：

```bash
fio --direct=1 --ioengine=libaio --iodepth=64 --numjobs=4 \
  --output-format=json ...
```

fio 文件必须位于真实块设备文件系统，不能位于 tmpfs/overlay。负载结束后 5 秒内 I/O inflight
应回到 0，session 中 `completion_miss` 必须为 0；否则该轮是采集完整性失败，不可计为 TP。
内存正例根据启动时的 MemAvailable 动态扩 worker（最多 64），优先保持每 worker 128 MiB/s，绝不
超过 160 MiB/s；必须实际跨过 15% 且继续定速触页至少 5 秒，或由日志确认 workload OOM victim。
syscall 正例必须在结束时证明实测速率达到 `max(10000, 0.8*target)`，否则同样记基础设施失败。

### Oracle 与计分

正例报告必须同时满足以下三项才算 TP：

1. `anomaly_type` 匹配注入类型；
2. `root_cause_code` 匹配该 workload 的预期代码；
3. `related_object` 命中独立采集的 TGID/TID/device/lock/syscall oracle。

锁主用例不能用 `sync.Mutex` 充当地址 oracle：它的慢路径先在 Go runtime 内停车 goroutine，内核
`do_futex` 看到的可能是 runtime 的线程停车字，而不是该 `sync.Mutex` 实例。`rca-testload lock`
因此使用显式 CAS + `FUTEX_WAIT_PRIVATE` word，并在 `workload.log`/`lock-oracle.json` 保存同一
`uaddr`、不同 waiter TID 和 wait/wake 计数。该地址同时写入 `ground_truth.json`；主 checker 按
TGID/TID/exact-address 绑定同一对象，报告若给出另一个地址会按 FP+FN 计数，不能 PASS。

正例缺少匹配报告记 FN；负例出现任一报告记 FP；正例中所有不匹配的额外异常类型同样计 FP，
不能只放进 warning。collector/session/schema/tool/workload/truth/health 失败由 `run_status.json`
单列 `infra_error`，不得混入 TN 或从分母静默删除；checker 因真实 FN/FP 非零退出仍按 confusion
matrix 计数。根因 code 与对象 Top-1 必须绑定同一份 Top-1 报告：先取 `confidence` 最高者，同分取输出
最早者，不能分别在不同报告中做 any-match。汇总报告宏平均 precision/recall/F1、根因 code 正确率
和对象 Top-1 命中率。

验收目标：宏平均 F1 >= 90%，根因 code 正确率 >= 85%，对象 Top-1 >= 90%，空载误报率 <= 5%。
定向 `--target-pid` 诊断可以单独统计，但不能替代主结果。

## 4. 开销与资源

性能测试使用配对且交替顺序的 baseline/with-tool，每个 case 至少 5 轮，并包含 combined
`--scenario all`：

```bash
make bench-full
bash scripts/bench_overhead.sh --scenario all --duration 60 --repeat 5 --out outputs/bench
```

必须解析 baseline 与 with-tool 两侧真实 workload 指标：stress-ng bogo ops，或 fio IOPS、带宽和
P99；不能用固定 timeout 的墙钟时间替代吞吐。工具 CPU 为用户态进程 CPU 加 BPF
`ProgramInfo.Runtime/RunCount`，内存为 RSS 加 BPF map memory。判读和产物见
[overhead_test.md](overhead_test.md)。

目标为吞吐下降 <= 5%、P99 增幅 <= 5%、all-mode 总内存 <= 64 MiB。达标结论只能引用新脚本的
原始数据与 manifest，不能沿用旧的三轮结果。

## 5. x86_64 / ARM64 平台验收

两台 openKylin 机器分别运行同一入口：

```bash
bash scripts/platform_acceptance.sh \
  --out "outputs/platform/$(uname -m)-$(date -u +%Y%m%dT%H%M%SZ)" \
  --soak-duration 30m --accuracy-repeat 10 --bench-repeat 5
```

脚本从 `HEAD` 导出 clean snapshot，直接消费已提交 bpf2go Go/ELF 产物完成 unit/build；随后把
同一 archive 解压到第二棵临时树，只在那里运行目标机 `make vmlinux generate` 及重生成后的
unit/build，工作区始终不被修改。正式五场景 E2E、30 分钟严格 all-mode soak、准确率和性能最终
仍从第一棵未重生成的树运行。两树的 SHA256/二进制 diff 与 equality flag 都会保留，但 CO-RE
local BTF 随内核配置或架构造成的字节漂移不算失败。非 openKylin、Kernel < 6.6、非
x86_64/ARM64、BTF 缺失或源码工作区不干净都会立即失败。验收要求每个平台独立保留：

- `environment.txt` 与 `commands.log`；
- `platform_check.txt`、clean source archive、三阶段 generated hash、二进制 diff 与 equality flag；
- 原始 workload/tool 日志和合法 `DiagnosticSession`；
- checker/schema 输出，而不是只保留汇总 Markdown；
- all-mode collector 健康计数、BPF runtime/run-count/map memory；
- 可由 `sha256sum -c SHA256SUMS` 复核的 manifest。

amd64 通过不能外推 ARM64 通过；ARM64 也必须跑完整 E2E/soak/benchmark。RISC-V 本轮只保留
little-endian 构建兼容性，不宣称实机验收。

建议以普通用户启动该脚本并确保 `sudo -n` 可用；脚本只在加载 BPF 的阶段提权，避免生成文件与
Go cache 变成 root 所有。

## 6. 证据状态

仓库中 2026-07-09 及更早的 `outputs/accuracy`、`outputs/bench` 使用过单场景、正例专用阈值、
`--target-pid`、三轮或宽松额外报告口径，不能支持“100% 准确率”或“低开销”结论。它们只能作为
历史调试样本。最终技术报告只引用按本文件重新生成的 x86_64/ARM64 platform bundle。
