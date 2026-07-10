# ebpf-rca 评分细则对齐清单

总分按功能完成度 40、诊断准确性 30、性能开销 15、工程质量 15 对齐。每项必须能从命令追溯到
原始 artifact；collector 失败、空文件或宽松解析不能计为“未发现异常”或 PASS。

## 1. 评分项与证据

| 大项 | 证明内容 | 机器证据 | 复核入口 |
|---|---|---|---|
| 功能完成度 40 | 五类 collector 在 strict all-mode 同时加载；JSON/YAML/Markdown；环境与对象字段正确 | `DiagnosticSession.collectors[]`、`reports[]`、两个 JSON Schema | `make build`；`scripts/test_local.sh all`；`validate_report.py` |
| 诊断准确性 30 | 类型、`root_cause_code`、独立 workload 对象 oracle 同时匹配；额外报告计 FP | 每轮 session/ground truth/check、confusion matrix、macro F1、code/Top-1 | `make accuracy-full` |
| 性能开销 15 | 真实 bogo ops/IOPS/带宽/P99；用户态+BPF CPU；RSS+map memory | 配对原始日志、tool session、process CSV、summary JSON | `make bench-full` |
| 工程质量 15 | clean build/unit、错误传播、健康状态、复现文档、x86/ARM bundle 与 manifest | CI、platform bundle、commands/environment、`SHA256SUMS` | `scripts/platform_acceptance.sh` |

结构化 report 保留比赛七个核心字段，并增加机器稳定字段：

```text
root_cause_code, confidence
related_object.pid(TGID), tid, lock_address, scope
time_window.start, end, elapsed_ms
```

`--format json` 的顶层不再是 report stream，而是唯一 `DiagnosticSession`；在线流使用
`--format jsonl`。默认 `--allow-partial=false`，all-mode 任一 collector 初始化/Poll 失败必须非零退出。

## 2. 根因代码与证据约束

| 类别 | 稳定 code | 最小因果证据 |
|---|---|---|
| CPU | `cpu.compute_hotspot` / `cpu.scheduler_pressure` | 进程/最热线程核数；scheduler code 还需 runq wait/count |
| I/O | `io.queue_congestion` / `io.device_latency` | P99 超阈值；queue code 还需时间加权平均队深 >=16 |
| 内存 | `mem.reclaim_pressure` / `mem.oom_victim` | 系统压力+进程贡献，或权威 `mark_victim` 事件 |
| 锁 | `lock.futex_contention` / `lock.kernel_sync_wait` | futex 地址+等待者聚合，或内核同步栈 |
| syscall | `syscall.high_frequency` / `syscall.high_latency` | 调用频率/累计耗时；等待型调用不能仅因 wall time 触发 |

禁止的无证据推断：上下文切换多即锁竞争、低队深 I/O 即 cache miss/热点文件、最大 RSS 即内存
肇事者、`waker_tid` 即持锁者、正常 epoll/futex 长等待即 syscall 热点。

## 3. 提交前硬性验收

每台 openKylin x86_64 和 ARM64 机器分别执行：

```bash
bash scripts/platform_acceptance.sh \
  --out "outputs/platform/$(uname -m)-$(date -u +%Y%m%dT%H%M%SZ)" \
  --soak-duration 30m --accuracy-repeat 10 --bench-repeat 5
```

bundle 必须包含并通过：

1. openKylin、Kernel 6.6+、目标架构、BTF 文件与 hash、工具链和 source commit；
2. `HEAD` clean snapshot 用已提交 bpf2go 产物通过 build/`go test ./...`，并承载正式 live 验收；
3. 第二棵 clean tree 完成目标机重生成和 unit/build，保存 SHA256、diff 与 equality flag；
4. 五场景 E2E 与严格 schema；
5. 30 分钟 `--scenario all --allow-partial=false` soak，五个 collector 状态正常；
6. 准确率：每类 workload 至少 10 轮，工具 all-mode、默认阈值、无 target；
7. 性能：每 case 至少 5 个配对轮次，奇偶轮交换顺序，含 combined all；
8. `sha256sum -c SHA256SUMS` 通过。

准确率目标：macro F1 >=90%、code >=85%、对象 Top-1 >=90%、idle FP <=5%。性能目标：吞吐
下降和 P99 增幅均 <=5%，all-mode RSS+map memory <=64 MiB。

## 4. 当前证据状态

代码和评测入口已按新接口组织，但最终 x86_64/ARM64 platform bundle 仍需在对应 openKylin 实机
重新生成。仓库内 2026-07-09 及更早的 accuracy/bench 输出使用过三轮、单场景、正例专用阈值、
`--target-pid` 或宽松 extra-report 口径，只能作为历史调试样本。

因此提交前不得沿用以下结论：

- “诊断准确率 100%”或“误报率 0%”；
- “低开销”或仅凭工具进程 RSS/CPU 推导总开销；
- “x86 可编译所以 ARM64 已适配”；
- “输出文件非空所以场景 PASS”。

最终报告中的每个数字都应链接到平台 bundle 的 summary、原始轮次和 manifest。

## 5. 提交材料最小集合

1. 五类异常的合法 session/report 与根因 code/证据链截图；
2. x86_64、ARM64 两份环境和 30 分钟 soak 证据；
3. 严格 oracle confusion matrix、macro F1、code 与对象 Top-1；
4. 配对性能表：bogo/IOPS/带宽/P99、用户态+BPF CPU、RSS+map memory；
5. JSON Schema、collector health 和失败语义说明；
6. 一键造障到根因输出的视频，命令与对应 artifact 一致；
7. 两个平台可复核的 `SHA256SUMS`。
