# ebpf-rca 准确性与复现测试矩阵

本文件用于补技术报告第 4.1、4.4 节，重点证明异常识别正确率、根因定位正确率、低误报/低漏报。

## 1. 场景矩阵

| 编号 | 场景 | 注入负载 | 预期异常类型 | 预期根因关键词 | 必须出现的证据 |
|---|---|---|---|---|---|
| 1 | CPU | `stress-ng --cpu ... matrixprod` | CPU异常占用 | 计算热点、busy loop、CPU 饱和 | cpu_util、tid/pid、time_window |
| 2 | I/O | `fio randrw` | I/O延迟抖动 | 设备队列拥堵、P99 时延升高 | p99/avg latency、iops/throughput、queue_depth/dev |
| 3 | 内存 | `stress-ng --vm` | 内存抖动/OOM风险 | direct reclaim、kswapd、缺页 | reclaim_count/time、available memory、pid/comm |
| 4 | 锁竞争 | `stress-ng --mutex` | 锁竞争 | futex/mutex、off-CPU、唤醒链 | offcpu_ratio、block stack、waker/wakee |
| 5 | syscall | `dd bs=1` 或高频 read/write | 系统调用热点 | read/write/poll/fsync 高频或高耗时 | syscall name/no、count、latency/cost |

## 2. 测试步骤

评分复现链路使用 `run_all_repro.sh` 内置纯 workload，不调用 `scripts/repro_*.sh`；后者保留为“启动工具 + 注入负载”的演示脚本。运行前需要 root 或可非交互执行 `sudo -n`。

```bash
sudo -n bash scripts/env_check.sh
bash scripts/run_all_repro.sh --duration 60 --format json
python3 scripts/validate_report.py outputs/repro/*.json
```

`validate_report.py` 支持单个 JSON、JSON 数组、JSON Lines，以及 `json.Encoder.SetIndent` 产生的连续 pretty JSON 对象流；同一文件内所有 report 都会被检查。

## 3. 2026-07-08 单轮复现留档

| 场景 | 是否跑通 | 是否识别正确异常 | 根因是否命中 | 证据链是否充足 | 输出文件 | 备注 |
|---|---|---|---|---|---|---|
| CPU | PASS | PASS | PASS | PASS | `outputs/repro/cpu_report.json` | `CPU异常占用`，多窗口输出 |
| I/O | PASS | PASS | PASS | PASS | `outputs/repro/io_report.json` | `I/O延迟抖动`，包含设备与时延指标 |
| 内存 | PASS | PASS | PASS | PASS | `outputs/repro/mem_report.json` | `内存抖动`，包含 reclaim/RSS/可用内存证据 |
| 锁竞争 | PASS | PASS | PASS | PASS | `outputs/repro/lock_report.json` | `锁竞争`，包含 off-CPU/futex 证据 |
| syscall | PASS | PASS | PASS | PASS | `outputs/repro/syscall_report.json` | `系统调用热点`，包含 syscall 名称、次数、耗时证据 |

结构化校验覆盖 `outputs/repro/*.json` 和 `outputs/bench/tool_output/*.json` 后结果为：CPU 76 份、I/O 10 份、lock 1322 份、mem 4 份、syscall 684 份，全部 PASS，平均分 100.0。

## 4. 2026-07-08 多轮 oracle 准确率

命令：

```bash
make accuracy-full
```

评测口径见 `outputs/accuracy/accuracy.md`：正例要求报告命中本次 workload 的 pid/tid/device oracle；负例要求空载窗口无报告。实测为 9 个场景 × 3 轮，共 27 轮。

| 场景 | 类型 | 运行数 | TP | TN | FP | FN | 准确率 | 召回率/误报率 | 备注 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| CPU | positive | 3 | 3 | 0 | 0 | 0 | 100.0% | 召回 100.0% | 命中 stress-ng CPU workload |
| I/O | positive | 3 | 3 | 0 | 0 | 0 | 100.0% | 召回 100.0% | 命中 fio 所在块设备 |
| 内存 | positive | 3 | 3 | 0 | 0 | 0 | 100.0% | 召回 100.0% | target 进程树过滤后命中 `stress-ng-vm` |
| 锁竞争 | positive | 3 | 3 | 0 | 0 | 0 | 100.0% | 召回 100.0% | target 进程树过滤后命中 `stress-ng-futex` |
| syscall | positive | 3 | 3 | 0 | 0 | 0 | 100.0% | 召回 100.0% | 命中高频 read/write workload |
| idle_cpu | negative | 3 | 0 | 3 | 0 | 0 | 100.0% | 误报 0.0% | 空载无告警 |
| idle_io | negative | 3 | 0 | 3 | 0 | 0 | 100.0% | 误报 0.0% | 空载无告警 |
| idle_lock | negative | 3 | 0 | 3 | 0 | 0 | 100.0% | 误报 0.0% | 空载无告警 |
| idle_syscall | negative | 3 | 0 | 3 | 0 | 0 | 100.0% | 误报 0.0% | 空载无告警 |

总体结果：有效运行 27/27，诊断准确率 100.0%，端到端通过率 100.0%。图表见 `outputs/accuracy/pass_rate_by_scenario.svg` 和 `outputs/accuracy/error_breakdown.svg`。

## 5. 场景级混淆矩阵

这里使用二分类 oracle 口径：正例命中本次 workload 记为 TP，正例未命中记为 FN；负例无告警记为 TN，负例有告警记为 FP。

| 实际场景 | TP | TN | FP | FN | infra_error |
|---|---:|---:|---:|---:|---:|
| CPU | 3 | 0 | 0 | 0 | 0 |
| I/O | 3 | 0 | 0 | 0 | 0 |
| 内存 | 3 | 0 | 0 | 0 | 0 |
| 锁竞争 | 3 | 0 | 0 | 0 | 0 |
| syscall | 3 | 0 | 0 | 0 | 0 |
| 空载合计 | 0 | 12 | 0 | 0 | 0 |

## 6. 技术报告可用结论模板

> 单轮复现留档中，五类异常均能产生对应类型诊断并输出结构化证据链。进一步使用 `make accuracy-full` 做 27 轮 oracle 评测，CPU、I/O、内存、锁竞争、syscall 五类正例 15/15 命中 workload oracle，四类空载负例 12/12 无误报；总体诊断准确率 100.0%，端到端通过率 100.0%。历史版本中 mem/lock 被后台进程污染的问题，已通过 workload 进程树过滤和测试脚本 ground truth 绑定修复。
