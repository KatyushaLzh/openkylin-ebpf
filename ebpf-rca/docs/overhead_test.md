# ebpf-rca 严格性能开销基准

性能结论的核心不变量是：比较同一 workload 的真实工作量，不用固定 timeout 的墙钟时间冒充
吞吐；同时计入用户态和 BPF 内核态资源。当前文档定义方法，不预填未经新口径复跑的数字。

## 1. 配对实验设计

每个 case 做至少 5 个配对轮次：

```text
baseline  = 只运行 workload
with_tool = 同一 workload + 一个 ebpf-rca 实例
```

奇数轮 baseline 先跑，偶数轮 with-tool 先跑，以减弱 cache 温度、后台抖动和设备状态随时间
漂移造成的顺序偏差。两相之间有 cooldown，工具在 workload 前 warmup，并在结束后保留 margin
写出完整 `DiagnosticSession`。缺失任一相、工具非零退出、session partial 或指标无法解析都会让
整次汇总失败。

基准汇总在读取 collector health 前复用 `scripts/validate_report.py` 的严格 session 校验：重复键、
未知/缺失字段、非有限数以及时间、collector 生命周期和报告语义错误都会使证据失效；不会先从
部分合法的 JSON 中提取开销数据。

`--scenario all` 运行 6 个 case：五个单 collector case 加一个 combined all-mode case。单场景
case 用于归因每类探针成本；combined case 同时运行 CPU、内存、锁、syscall stressor 与 fio，验证
五 collector 并发时的资源上界。

## 2. Workload 与观测指标

| case | workload | baseline/with-tool 都必须解析的指标 |
|---|---|---|
| CPU | `stress-ng --cpu ... matrixprod --metrics-brief` | bogo ops、bogo ops/s |
| I/O | fio direct randrw | IOPS、带宽、P99 completion latency |
| 内存 | `stress-ng --vm ... --metrics-brief` | bogo ops、bogo ops/s |
| 锁 | `stress-ng --mutex ... --metrics-brief` | bogo ops、bogo ops/s |
| syscall | `stress-ng --syscall ... --metrics-brief` | bogo ops、bogo ops/s |
| all | 上述 stressor + fio 并发 | 汇总 bogo ops/s + IOPS/带宽/P99 |

fio 固定关键参数：

```text
--direct=1 --ioengine=libaio --iodepth=64 --numjobs=4 --output-format=json
```

测试文件必须位于真实块设备文件系统。脚本从 fio JSON 解析 read/write IOPS、`bw_bytes` 和最接近
99.0 的 latency percentile；非正数、缺字段或非有限值均失败。stress-ng 同样要求真实 metrics
行和正 bogo 值，不把“进程运行了 60 秒”当作有效测量。

## 3. 开销定义

设 baseline 吞吐为 `B`、with-tool 吞吐为 `T`，baseline/with-tool P99 为 `L0/L1`：

```text
吞吐下降(%) = (B - T) / B * 100
P99 增幅(%) = (L1 - L0) / L0 * 100
```

负下降或负增幅原样保留，不能截成 0 或用其宣称工具“加速”了负载；它通常反映实验噪声，需结合
多轮均值和离散程度解释。

资源口径：

- 用户态 CPU：`/proc/<pid>/stat` 的 `utime+stime` 差分 / 采样墙钟时间；
- BPF CPU：session 内全部 collector 的 `program_runtime_ns / workload_elapsed_ns`；runtime 覆盖 warmup、workload 与 drain，并全部保守计入 workload 时长，避免用空闲尾段稀释；
- 合计 CPU：用户态 CPU% + BPF CPU%；BPF `program_run_count` 同时保留用于解释事件量；
- 用户态内存：`VmRSS/VmHWM` 的峰值；
- BPF 内存：collector health 的全部 `map_memory_bytes` 之和；`counters.map_memory_estimated=0`
  表示每个 map 都来自 fdinfo memlock 精确值；
- 合计内存：工具进程峰值 RSS + BPF map memory。

`DiagnosticSession.collectors[]` 必须全部 `initialized=true,state=stopped`，没有 `health_error`，且
runtime/run-count/map-memory 为有效值。collector 失败绝不能解释为开销为零。内核不暴露 fdinfo
memlock 时，health 仍可用逻辑容量回退做运行观测，但会置
`counters.map_memory_estimated=1`；正式基准直接拒绝该证据，不能用估算值验收 64 MiB 目标。

## 4. 一键运行

```bash
cd ebpf-rca
make build
bash scripts/bench_overhead.sh \
  --scenario all --duration 60 --repeat 5 --out outputs/bench
```

默认需要可非交互 `sudo -n`；root 环境自动省略 sudo。脚本严格要求 `repeat >= 5`。正式平台证据
建议通过统一入口生成：

```bash
bash scripts/platform_acceptance.sh \
  --soak-duration 30m --accuracy-repeat 10 --bench-repeat 5
```

## 5. 产物与复核

| 路径 | 内容 |
|---|---|
| `outputs/bench/bench_runs.tsv` | 每个 phase 的状态、顺序与原始文件索引 |
| `outputs/bench/raw/*` | stress-ng 日志、fio JSON/stderr、解析后的 workload metrics、工具日志 |
| `outputs/bench/tool_sessions/*_session.json` | with-tool 严格 `DiagnosticSession` 与 collector health |
| `outputs/bench/resource/*_process.csv` | `/proc` CPU/RSS/HWM 采样 |
| `outputs/bench/bench_summary.csv` | 每个配对轮次的原始派生指标 |
| `outputs/bench/bench_summary.json` | 方法、数据错误、case 汇总与目标判定 |
| `outputs/bench/bench.md` | 从同一结构化结果生成的阅读版表格 |

复核顺序：先检查 `bench_summary.json.valid=true`、`errors=[]` 和 `acceptance_pass=true`，再检查轮数与奇偶顺序，最后从
TSV 追溯任一汇总单元格到 workload JSON、session 和 process CSV。platform bundle 还会记录命令、
环境和 `SHA256SUMS`，避免只提交可修改的汇总表。

## 6. 验收目标与结论边界

- 吞吐下降 <= 5%；
- fio P99 增幅 <= 5%；
- combined all-mode 合计内存 <= 64 MiB；
- x86_64 与 ARM64 分别完成同一套至少 5 轮配对测试。

脚本在证据无效或任一目标失败时都返回非零。只有新 bundle 的结构化汇总 `valid=true`、
`acceptance_pass=true` 且目标通过时，技术报告才能写“满足开销目标”，并应同时
给出均值、轮数、平台和原始证据路径。2026-07-09 及更早的三轮表没有 BPF runtime/map memory、
交替顺序和 combined all-mode 证据，不能支持“低开销”结论。

## 7. 优化检查清单

- map 有明确容量和失败健康计数，长时间运行后无不可解释增长；
- 内核态只聚合必要状态，不逐事件上送；用户态使用真实 elapsed 做窗口差分；
- syscall enter 使用 LRU map；I/O partial completion 最终能清空 request state；
- 只有需要的场景才加载对应 collector，另用 combined all case 测最坏组合；
- 栈解析与 Markdown 渲染留在用户态，异常确认后再做；
- 报告平均值之外保留每轮数据、顺序、峰值与失败样本，不挑选最好看的单次结果。
