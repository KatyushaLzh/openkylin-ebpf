# ebpf-rca 评分细则对齐清单

本清单用于最后提交前逐项自查。目标是把“功能完成”变成“材料可证明”。

| 评分项 | 分值 | 满分证据 | 本项目对应文件/命令 |
|---|---:|---|---|
| 场景覆盖数量 | 15 | CPU、I/O、内存、锁竞争、syscall 五类都能跑 | `make repro-all`；`outputs/repro/repro_summary.md` |
| 结构化输出完整性 | 15 | 7 个核心字段齐全，JSON/YAML/Markdown 可解析 | `schemas/anomaly_report.schema.json`；`make validate-output` |
| 多平台适配 | 10 | openKylin Kernel 6.6+，x86_64/ARM64，尽力 RISC-V | `sudo -n bash scripts/env_check.sh`；保存不同机器的 `outputs/env/env_report.md` |
| 异常识别正确率 | 10 | 注入负载后能识别，空载不误报，形成混淆矩阵 | `make accuracy-full`；`outputs/accuracy/accuracy.md` |
| 根因定位正确率 | 12 | 根因措辞贴近官方参考根因，定位到进程/线程/设备/syscall/锁热点 | `outputs/repro/*_report.json`；`outputs/accuracy/accuracy_summary.csv`；`outputs/validation/schema_check.md` |
| 证据链一致性 | 8 | 结论与 metric/event/stack/log 相互印证 | `evidence_chain` 字段；`validate_report.py` 检查 |
| CPU 开销 | 4 | 工具平均/峰值 CPU% 有实测数据 | `make bench-full`；`outputs/bench/bench.md` |
| 内存开销 | 3 | 工具平均/峰值 RSS 有实测数据 | `outputs/bench/resource/*.csv` |
| 时延影响 | 4 | baseline vs with_tool 的耗时/P99 对比 | `outputs/bench/bench.md` |
| 吞吐影响 | 4 | I/O 吞吐、IOPS 或 workload 完成时间变化 | `outputs/bench/bench_summary.csv` |
| 代码规范 | 4 | 脚本有参数、有错误处理、有清晰目录 | `scripts/*.sh`、`scripts/*.py` |
| 文档完整性 | 4 | 安装、使用、参数、设计、限制、测试说明齐全 | `docs/overhead_test.md`、`docs/testing_matrix.md` |
| 复现脚本 | 4 | 一键部署 + 一键复现五场景 | `scripts/run_all_repro.sh` |
| 测试说明 | 3 | 测试步骤、输入输出、结果示例完整 | `outputs/*/*.md` 与本文档 |

## 提交前硬性自查

```bash
make build
sudo -n bash scripts/env_check.sh
make repro-all
make accuracy-full
make bench-full
make validate-output
```

## 当前实测状态

- 环境：openKylin 2.0 SP2，Kernel 6.6.0-22-generic，x86_64，root 运行；`outputs/env/env_report.md` 为 PASS 26、WARN 1、FAIL 0。
- 五类复现：`make repro-all` 生成 `outputs/repro/{cpu,io,mem,lock,syscall}_report.json`，5/5 PASS。
- 多轮准确率：`make accuracy-full` 完成 9 场景 × 3 轮，27/27 有效，诊断准确率 100.0%，端到端通过率 100.0%。CPU/I/O/mem/lock/syscall 正例全部命中 workload oracle，四类 idle 负例误报率 0%。
- 结构化校验：`make validate-output` 覆盖 repro 与 benchmark tool JSON，五类全部 PASS，平均分 100.0。
- 开销基准：`make bench-full` 完成 5 场景 × 3 轮 baseline/with_tool，结果见 `outputs/bench/bench.md`。

## 已修复的准确率短板

- 内存：旧版会在桌面环境下选择后台 `code` 进程；当前 mem collector 在 target 模式下只扫描 workload 进程树 RSS，并过滤 BPF map 中非目标 TGID，三轮均命中 `stress-ng-vm`。
- 锁竞争：旧版会输出大量桌面/编辑器线程；当前 lock eBPF 和用户态 collector 同步 workload 子进程 TGID，只保留目标 TID，三轮均命中 `stress-ng-futex`。
- syscall：保留 `--target-pid` 进程树过滤，避免全局 `raw_syscalls` 背景噪声污染复现结果。

提交材料中至少要出现：

1. 五类场景各一份 JSON/Markdown 诊断输出；
2. 一张多轮准确率 / 误报率图表；
3. 一张 baseline vs with_tool 工具开销表；
4. 一张结构化输出字段说明或 schema；
5. 一张 openKylin + Kernel + BTF 环境截图；
6. 一段“一键造障→自动定位→证据链”的演示视频。
