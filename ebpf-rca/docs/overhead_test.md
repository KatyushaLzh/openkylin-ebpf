# ebpf-rca 工具开销评测体系

本文件用于支撑技术报告第 4.2 节“性能开销基准”，并记录评分验收脚本的实际运行方式与当前实测结果。

## 1. 评测目标

评分细则里与开销相关的分项包括 CPU 开销、内存开销、时延影响、吞吐影响；同时，性能评测脚本还能复用到复现脚本、测试说明、文档完整性等工程质量分项。我们的目标不是只说“低开销”，而是给出可复核的数字证据。

## 2. 实验设计

采用两态对照法：

```text
baseline：不加载 ebpf-rca，只运行异常注入负载
with_tool：先加载 ebpf-rca，再运行同样异常注入负载
```

`bench_overhead.sh` 不调用 `scripts/repro_*.sh`，因为这些演示脚本本身会启动 `ebpf-rca`。benchmark 内置纯 workload，保证 baseline 只跑负载，with_tool 只额外启动一个工具实例。脚本会用 `ps` 周期采样工具进程 CPU/RSS；在 sudo/root 场景下按子进程 PID 采样，避免资源数据为空。

每个场景至少重复 3 次，取平均值，保留原始日志。当前测试场景覆盖：

| 场景 | benchmark 负载 | 主要关注指标 |
|---|---|---|
| cpu | `stress-ng --cpu ... matrixprod` | 工具 CPU%、RSS、负载耗时增幅 |
| io | `fio randrw` | IOPS、平均/P99 时延、吞吐、队列深度 |
| mem | `stress-ng --vm` | 工具 RSS、direct reclaim 诊断稳定性 |
| lock | `stress-ng --mutex` 或 `--futex` | off-CPU 阻塞证据、工具 CPU/RSS |
| syscall | `dd bs=1` 高频 read/write | 高频 syscall 诊断、事件量较大时的开销 |

## 3. 一键运行

前提：当前环境需要 root，或可非交互执行 `sudo -n`。如果进程被设置 `no_new_privs`，或缺少 `CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE`，脚本会快速失败，不再白跑 workload。

```bash
# 1. 环境检查，生成 outputs/env/env_report.md
sudo -n bash scripts/env_check.sh

# 2. 五类场景复现，生成 outputs/repro/*.json
bash scripts/run_all_repro.sh --duration 60 --format json

# 3. 工具开销 benchmark，生成 outputs/bench/bench.md
bash scripts/bench_overhead.sh --scenario all --duration 60 --repeat 3 --out outputs/bench

# 4. 结构化输出校验，生成 outputs/validation/schema_check.md
python3 scripts/validate_report.py outputs/repro/*.json outputs/bench/tool_output/*.json
```

Makefile 已内置评分产物生成目标：

```bash
make env-check
make repro-all
make bench-full
make validate-output
make report-artifacts
```

## 4. 输出文件说明

| 路径 | 用途 |
|---|---|
| `outputs/env/env_report.md` | 运行环境、多平台适配证据 |
| `outputs/repro/repro_summary.md` | 五类异常复现结果汇总 |
| `outputs/repro/*_report.json` | 每类异常的结构化输出样例 |
| `outputs/bench/bench.md` | 性能开销总表，可直接贴进技术报告 |
| `outputs/bench/bench_summary.csv` | 原始汇总数据，便于画图或复核 |
| `outputs/bench/resource/*.csv` | 工具进程 CPU/RSS 逐秒采样 |
| `outputs/bench/tool_output/*.json` | benchmark 阶段每轮工具 JSON 输出 |
| `outputs/validation/schema_check.md` | 输出 schema 与证据链质量检查 |

## 5. 技术报告可用表格

2026-07-08 在 openKylin 2.0 SP2、Kernel 6.6.0-22-generic、x86_64 上的实测结果如下；原始表见 `outputs/bench/bench.md`。

| 场景 | 基线平均耗时(s) | 加载后平均耗时(s) | 平均变慢% | 工具平均CPU% | 工具峰值CPU% | 工具平均RSS(MB) | 工具峰值RSS(MB) | JSON有效/运行数 | 最小证据链长度 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cpu | 60.013 | 60.013 | 0.000% | 0.038% | 0.100% | 8.807 | 10.656 | 3/3 | 3 |
| io | 61.816 | 61.930 | 0.183% | 0.000% | 0.000% | 5.598 | 5.660 | 3/3 | 6 |
| mem | 60.134 | 60.139 | 0.008% | 1.143% | 1.600% | 9.800 | 10.852 | 3/3 | 10 |
| lock | 60.015 | 60.020 | 0.008% | 0.613% | 3.600% | 43.035 | 51.371 | 3/3 | 13 |
| syscall | 60.004 | 60.004 | 0.000% | 0.433% | 0.600% | 10.093 | 10.785 | 3/3 | 7 |

## 6. 满分答辩口径

> 我们对每类异常都做了 baseline 和 with_tool 两态对照，并重复多轮。评测不只看工具进程自身 CPU 和 RSS，也看负载耗时、I/O P99、吞吐等端到端影响。所有原始日志、资源采样 CSV、工具 JSON 输出和结构化校验报告都随仓库提交，评委可以直接复现。因此“低开销”不是口头描述，而是可验证数据。

## 7. 开销优化检查清单

- eBPF 程序内核态只做聚合，不逐事件全量上送。
- 用户态按采样窗口差分，避免高频轮询。
- `--scenario` 按需开启探针，避免默认全量探针。
- `--interval`、`--threshold`、`--sustain` 可配置，平衡灵敏度与开销。
- map 大小设置上限，避免长时间运行内存膨胀。
- 调用栈、符号化、Markdown 渲染等重操作只在异常确认后执行。
- benchmark 保留平均值与峰值，不只报最好看的单次结果。
- `outputs/` 下的 CSV/JSON/Markdown 是评测产物；源码提交可只保留 `.gitkeep`，答辩材料则应保留本次实测产物。
