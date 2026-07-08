# 设计说明

## 1. 目标与原则

实现一套低开销的系统异常观测与**根因定位**工具，输出带证据链的结构化诊断。

- **低开销**：内核态只做按线程聚合（hash map），不做 per-event 上送；用户态按窗口差分读取。
- **零幻觉、可回溯**：根因判定全部走确定性规则，每条结论附带可追溯证据；LLM 仅可用于上层报告润色，不参与判定。
- **可扩展**：采集/检测/推断/输出分层解耦，新增异常场景 = 新增一组探针 + 检测器 + 推断规则。

## 2. 数据流

```
sched_switch / sched_wakeup (tracepoint)
        │  内核态：按 tid 累计 run_ns / runq_ns / ctx
        ▼
   stats/oncpu_start maps ──(用户态按 interval 读取 + 差分)──▶  Sample{cpu_util, ctx/min, runq_wait}
        ▼
   detector：阈值 + 连续窗口判定  ──▶  Signal
        ▼
   rca：规则分类根因 + 组装 evidence_chain  ──▶  AnomalyReport
        ▼
   output：JSON / YAML / Markdown
```

## 3. 场景①的指标计算

| 指标 | 来源 | 计算 |
|---|---|---|
| `cpu_util` | `run_ns` 差分 + 当前 on-CPU 补偿 | `Δrun_ns / interval_ns`，1.0 ≈ 占满一核 |
| `ctx_switch_per_min` | `ctx` 差分 | `Δctx / interval_min` |
| `runq_wait_us` | `runq_ns`、`ctx` 差分 | `Δrunq_ns / Δctx / 1000` |

## 4. 根因分类规则（场景①）

- `cpu_util ≥ 阈值` 且 `ctx_switch_per_min` 低 → "用户态计算热点导致 CPU 饱和（计算密集 / busy loop）"
- `cpu_util ≥ 阈值` 且 `ctx_switch_per_min` 高(≥5万/分) → "频繁上下文切换，疑似锁竞争/频繁唤醒"

措辞对齐赛题"参考根因"词表，以契合"根因定位正确率"评分。

## 4a. 场景②：I/O 延迟抖动（块层时延）

在 `block_rq_issue` 记录请求起点并使队列深度 +1；当前 tracepoint 不暴露 request 指针，
因此 key 使用 `dev+sector+nr_sector+rwbs`，比单纯 `dev+sector` 更不易冲突，但仍不是绝对唯一。
在 `block_rq_complete` 命中起点后才结算时延并使队列深度 -1；未命中不扣队列深度，避免负数。
时延进入 log2(ns) 直方图，用户态按窗口差分估算 P99 和窗口最大值。

| 证据 | 来源 | 含义 |
|---|---|---|
| `iops` | `count` 差分 / 窗口 | 每秒完成请求数 |
| `avg_lat_ms` | `total_lat_ns`/`count` 差分 | 平均完成时延 |
| `p99_lat_ms` | `slots[]` 直方图差分 | P99 完成时延(取槽位上界 2^slot) |
| `max_lat_ms` | `slots[]` 直方图差分 | 窗口内最大完成时延估算值(槽位上界) |
| `throughput_mbps` | `bytes` 差分 / 窗口 | 吞吐 |
| `queue_depth` | `inflight` gauge | 当前在途请求数 |

根因判定：队列深度高(≥16) → "设备队列拥堵(队列过深)"；否则 → "访问集中/缓存失效"。
关联对象记为块设备(`major:minor name`，经 /proc/partitions 解析)。
> 提示：tracepoint 字段偏移随内核版本可能变化，必要时按 `events/block/block_rq_issue/format` 校正。

## 4b. 场景③：内存抖动 / 回收压力

核心信号是**直接回收(direct reclaim)**：进程分配内存时若内存不足会被迫同步回收，
危害最大。`mm_vmscan_direct_reclaim_begin/end` 按线程(tid)记录 begin，再按进程(tgid)
聚合直接回收次数与耗时，避免同进程多线程 begin 覆盖；`mm_vmscan_kswapd_wake` 统计后台回收唤醒。这些 tracepoint 跨架构、
字段无关，开销极低。可用内存与 per-process 缺页由用户态读 /proc 补充（避免高频 kprobe）。

| 证据 | 来源 | 含义 |
|---|---|---|
| `mem_available_pct` | /proc/meminfo | 可用内存占比 |
| `kswapd_wakes` | `mm_vmscan_kswapd_wake` 差分 | 后台回收活跃度 |
| `direct_reclaim_count` | direct_reclaim 差分 | 肇事进程直接回收次数 |
| `direct_reclaim_ms` | begin/end 配对 | 直接回收耗时 |
| `major_fault`/`minor_fault` | /proc/<pid>/stat 差分 | 缺页增量 |
| `rss_kb`/`anon_rss_kb` | /proc/<pid>/status | RSS/匿名 RSS 采样 |
| `rss_delta_kb`/`anon_rss_delta_kb` | /proc 快照差分 | 窗口内 RSS/匿名 RSS 增长 |

触发条件不是只看低 `MemAvailablePct`：低可用内存、`kswapd_wakes`、direct reclaim、
major fault、RSS/AnonRSS 快速增长任一强信号成立即可进入连续窗口判定。
根因归因优先级为 direct reclaim > major fault > RSS/AnonRSS 增长 > 最大 RSS > 系统级压力。
仍无明确对象时输出系统级低内存/OOM 风险，不伪造 pid=0 culprit。
**这是一个混合采集的刻意设计**：eBPF 抓因果事件(谁触发回收)，/proc 补系统上下文。

## 4c. 场景④：锁竞争（off-CPU + 唤醒链）

核心是 **off-CPU 阻塞归因**：在 `sched_switch` 中，当 `prev_state != 0`（被阻塞切出，
而非被抢占）时记录起点并抓取内核栈；线程重新上 CPU 时结算阻塞时长，按线程累计
off-CPU 阻塞时间/次数/最大值与阻塞栈 id。`sched_wakeup` 记录唤醒者，构成
**waker→wakee 唤醒链**，定位疑似持锁方。`--target-pid` 非 0 时，用户态会周期性解析
目标 root pid 的子进程树，并让内核态只记录这些 tgid 的 off-CPU 起点与对应唤醒事件，
用于降低背景线程正常等待带来的噪声。

| 证据 | 来源 | 含义 |
|---|---|---|
| `offcpu_ratio` | `offcpu_ns` 差分 / 窗口 | 阻塞型 off-CPU 占墙钟比例 |
| `max_offcpu_ms` | 阻塞时长直方图差分 | 窗口内最长阻塞估算值(槽位上界) |
| `block_count` | `offcpu_count` 差分 | 窗口内阻塞次数 |
| `last_waker_tid` | `sched_wakeup` current | 唤醒链上游(疑似持锁方) |
| 阻塞栈帧 | `stackmap` + /proc/kallsyms 符号化 | "线程堆栈聚集"证据 |
| `stack_status` | 用户态符号解析状态 | 栈是否成功符号化 |

根因判定：阻塞栈含 `futex/mutex/rwsem/down_/__lock/flock/locks_/filelock/posix_lock`
等锁/同步符号 → 判为"锁竞争"，否则判为"长时间阻塞等待"（疑似 I/O / 同步等待）。
默认只输出命中锁/同步符号的样本；`--lock-include-blocking` 可保留普通长阻塞，
`--lock-topn` 控制每个窗口输出的 Top-N 阻塞线程。符号化在用户态完成，内核态零额外上送。

## 4d. 场景⑤：系统调用热点（差异化项）

`raw_syscalls:sys_enter/sys_exit` 是通用 syscall tracepoint，跨 ABI 可移植。enter 记起点，
exit 结算单次耗时，按 `(进程, syscall号)` 累计次数/总耗时/最大耗时；syscall 号→名在
用户态按架构(amd64 专用表 / asm-generic 表)解析。可通过 `--target-pid` 只观测指定
root pid 及其子进程树，降低 `raw_syscalls` 全局挂载带来的开销。

| 证据 | 来源 | 含义 |
|---|---|---|
| `syscall` | nr→名解析 | 热点系统调用 |
| `calls_per_sec` | `count` 差分 | 调用频次 |
| `avg_lat_us` / `max_lat_us` | `total_ns`/`count`、直方图差分 | 单次耗时 / 窗口最大耗时估算值 |
| `total_ms_per_sec` | `total_ns` 差分 | 累计耗时占比 |
| `syscall_nr` | raw syscall id | 跨架构名称表缺失时的原始证据 |
| `target_pid` | CLI 配置 | 进程树过滤 root pid；0 表示全局 |

根因判定：等待型 syscall（如 `epoll_wait/poll/futex/nanosleep`）只在 calls/s 过高时报告，
表示短 timeout 轮询或唤醒风暴；非等待型 syscall 可由频次 ≥ 阈值 **或** 累计耗时
≥ 300ms/秒触发。单次平均耗时 ≥1ms 时判为"高耗时热点(阻塞型，如 fsync/慢 I/O)"，
否则判为"高频热点(忙轮询/未批处理)"。工具默认过滤 `comm=ebpf-rca` 自身。
> 注意：raw_syscalls 触发极频繁，是开销最高的场景；生产建议用 `--target-pid` 过滤目标进程。

## 5. 后续场景接入约定

每个新场景实现：
1. `bpf/<scene>.bpf.c`：采集探针，内核态聚合关键证据点。
2. `internal/collector/<scene>.go`：加载/读取，产出 `Sample`。
3. `internal/detector/<scene>.go`：异常判定，产出 `Signal`。
4. `internal/rca`：`Build<Scene>Report`，组装根因与证据链。

所有场景复用同一 `schema.AnomalyReport`，保证结构化输出一致、机器可解析。

## 6. 限制与权限

- 需 root 或 `CAP_BPF` / `CAP_PERFMON` / `CAP_SYS_ADMIN`。
- 依赖内核 BTF（CO-RE）；老内核缺 BTF 时需外置 BTF 或降级处理。
- CPU/锁场景的 `pid` 当前实为 tid；进程级/cgroup/container 聚合为后续工作。
- I/O key 在 tracepoint 无 request 指针时不是绝对唯一；高并发同扇区请求仍可能冲突。
- syscall 名表是常见子集；未知项以 `syscall_<nr>` 展示，并保留 `syscall_nr`。

## 7. 技术文档维护

- CLI、默认阈值、输出字段、BPF map、挂载点或复现脚本变化时，必须同步更新 `README.md`、`docs/testing.md` 和本设计文档。
- `README.md` 只放快速开始、参数表、输出示例和已知限制；实现细节放在本文件；openKylin 踩坑放在 `docs/troubleshooting.md`。
- 每次提交前运行 `make docs-check`，用真实 `--help` 输出反查 README，避免参数漂移。
- 示例输出应来自固定 mock report 或实际工具输出，不手写无法复核的字段。
