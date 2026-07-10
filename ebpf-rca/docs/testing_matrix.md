# ebpf-rca 准确性与复现测试矩阵

本矩阵定义正式评分 operating point。所有准确率主测试均运行五个 collector：
`--scenario all --allow-partial=false`，使用产品默认阈值与 sustain，不传 `--target-pid`。

## 1. 正例矩阵

| 场景 | 独立负载 | 期望异常类型 | 允许的 `root_cause_code` | 对象 oracle | 必查证据 |
|---|---|---|---|---|---|
| CPU | `rca-testload cpu` 单个 pinned busy thread | `CPU异常占用` | `cpu.compute_hotspot` | workload TGID，Top TID | `process_cpu_cores`、`top_thread_cpu_cores`、`runq_count`、真实窗口 |
| I/O 队列 | fio direct randrw，iodepth=64，numjobs=4 | `I/O延迟抖动` | `io.queue_congestion` | 测试文件所在块设备 | P99、`avg_queue_depth>=16`、IOPS/带宽、健康计数 |
| 内存压力/OOM | `rca-testload mem-pressure` 按 MemAvailable 动态扩 worker、跨 15% 后持续缺页 | `内存回收压力` / `OOM事件` | `mem.reclaim_pressure` / `mem.oom_victim` | workload TGID；无法定位时只允许 system scope | PSI、vmstat、direct reclaim/匿名 RSS 增长/major fault；`mem-oracle.json` 证明跨压持续>=5s或 OOM victim |
| futex 竞争 | `rca-testload lock --threads 8`（低 CPU、同一显式 futex word） | `futex锁竞争` | `lock.futex_contention` | workload 输出的 `uaddr`、TGID/TID，waiter>=2 | waiter count、总等待、P99/max、Top waiters、futex op、`lock-oracle.json` |
| syscall 热点 | 定速 `read`，结束时校验 achieved rate | `系统调用热点` | `syscall.high_frequency` | workload TGID 与 exact syscall name | calls/s、avg/P99/max、total ms/s；`syscall-oracle.json` |

每类至少 10 轮。不同根因变体应拆分用例：调度压力用例才接受 `cpu.scheduler_pressure`，设备服务
时延用例只能接受 `io.device_latency`；不能把同一异常大类下的任意 code 都算命中。
正式矩阵默认 `--workload deterministic`；`stress-ng` 只作为额外现实压力测试，不参与替代上述
低交叉标签、独立 oracle 的主结果。

## 2. 负例矩阵

| 场景 | 负载/状态 | 不应触发的原因 | 通过条件 |
|---|---|---|---|
| `idle` | 不注入 workload | 无持续异常 | `reports=[]`，五个 collector 全部正常停止 |
| `normal_mem` | 可容纳、无 PSI/reclaim 压力的 128 MiB 匿名申请 | 有 RSS 增长但不满足“系统压力 + 进程贡献” | 无内存报告 |
| `normal_epoll` | 长 timeout、低调用频率 epoll wait | 等待 wall time 长不是热点 | 无 syscall/锁误报 |
| `normal_io_sleep` | 低频 pipe reader 的普通阻塞 read | 无 futex 地址或同步栈；低频正常 read 等待也不是 syscall 热点 | `reports=[]`，尤其无锁/syscall 误报 |
| `normal_io_seq` | queue-depth-one、paced、O_DIRECT 顺序写 | 无高 P99 或队列拥堵 | 无 I/O 报告 |

每类至少 10 轮；任一额外报告均计 FP，而不是 warning。

## 3. 统一执行与 artifact

```bash
make accuracy-full
python3 scripts/eval_accuracy.py --scenario all --repeat 10 --out outputs/accuracy --require-acceptance
```

每轮必须保留：工具命令、`DiagnosticSession`、stderr、workload 原始日志、ground truth、checker、
`run_status.json` 分项退出码
结果和环境信息。JSON 以 `schemas/diagnostic_session.schema.json` 为顶层 schema，嵌套 report 以
`schemas/anomaly_report.schema.json` 校验；解析失败、collector 失败或 `partial=true` 都是
`infra_error`，不能按无告警 TN 处理。

I/O workload 固定核心参数：

```bash
fio --direct=1 --ioengine=libaio --iodepth=64 --numjobs=4 \
  --output-format=json ...
```

结束后等待最多 5 秒检查 collector health：inflight 必须回到 0，`completion_miss=0`；
`duplicate_issue/map_update_fail` 也应为 0，`partial_completion` 只记录合法 partial complete。

## 4. TP/FP/FN 规则

对正例报告 `r`，只有以下谓词同时为真才是匹配：

```text
type_match(r)
&& root_cause_code_match(r)
&& workload_object_oracle_match(r)
&& strict_schema_valid(r)
```

- 至少一个匹配报告：该正例有 1 个 TP；没有则有 1 个 FN。
- 同轮每个不匹配的额外报告都计 FP，包括错误异常类型、错误 code 或错误对象。
- 负例每个报告计 FP；零报告才计 TN。
- session/collector/tool/workload/truth/health 失败计 `infra_error`，原始轮次仍保留；checker 因 FN/FP
  非零退出仍是有效轮次，只有其 artifact 损坏或 `evaluation_valid=false` 才属于基础设施错误。
- type/code/object 准确率绑定同一 Top-1 报告；按 confidence 最高选择，同分取最早输出。

汇总必须同时给出逐类 confusion matrix、macro precision/recall/F1、根因 code 正确率、对象
Top-1 命中率和空载误报率。目标：macro F1 >= 90%、code >= 85%、Top-1 >= 90%、idle FP <= 5%。

## 5. 平台证据矩阵

| 项目 | openKylin x86_64 | openKylin ARM64 |
|---|---|---|
| Kernel 6.6+ 与 BTF hash | 必须保存 | 必须保存 |
| HEAD clean snapshot + 已提交 bpf2go 产物的 build/unit | 必须 PASS | 必须 PASS |
| 独立树目标机重生成 + build/unit | 必须 PASS 并保存 hash/diff | 必须 PASS 并保存 hash/diff |
| 五类 E2E | 必须 PASS | 必须 PASS |
| 30 分钟 strict all-mode soak | 必须 PASS | 必须 PASS |
| accuracy：全局默认、每类 >=10 轮 | 必须生成 | 必须生成 |
| benchmark：交替顺序、每 case >=5 轮 | 必须生成 | 必须生成 |
| 合法 JSON、原始数据、SHA256 manifest | 必须保存 | 必须保存 |

统一入口：

```bash
bash scripts/platform_acceptance.sh \
  --soak-duration 30m --accuracy-repeat 10 --bench-repeat 5
```

该入口会拒绝非 openKylin、Kernel < 6.6、非 x86_64/ARM64、BTF 缺失以及 `outputs/` 之外的
未提交项目改动。构建顺序是硬约束：先从 `HEAD` 导出不含历史 `outputs/` 的 clean snapshot，直接
使用仓库已提交的 `*_bpfel.go/.o` 完成 `go test ./...` 和 build；然后把同一 archive 解压到第二棵
临时树，在其中执行目标机 `make vmlinux generate` 和 unit/build，不修改工作区。最后的正式 live
E2E/soak/accuracy/benchmark 仍回到第一棵树运行。`validation/` 保存已提交/clean-build 后/目标机
重生成三份 SHA256 清单、二进制 diff，以及 `checked_in_equals_host_regenerated=true|false`。
由于 CO-RE object 的本地 BTF 会随内核配置和架构变化，`false` 是 provenance 而不是验收失败；
重生成本身或其 unit/build 失败才是基础设施失败。

## 6. 结论模板

在两个 platform bundle 均完成前，只能写“已建立可复核评测流程”，不能写具体准确率或开销
结论。完成后从 bundle 的结构化汇总自动填入样本数、混淆矩阵、macro F1、code/Top-1、吞吐和
P99 变化，并链接原始数据与 `SHA256SUMS`。旧三轮、定向 target、专用阈值结果标记为历史调试
数据，不并入最终统计。
