# 设计说明

## 1. 正确性边界

`ebpf-rca` 的核心目标是用可回溯证据定位系统异常根因。确定性规则负责判定，LLM 不参与
采集或分类。性能是需要 benchmark 证明的验收项，不把“内核态聚合”等设计选择直接等同于
“低开销”。

运行硬前提是 **openKylin、Kernel 6.6+、可读 BTF**，并且内核支持 typed BTF
tracepoint、`fentry/fexit` 和 per-CPU software perf event；lock 分类还要求 `/proc/kallsyms`
可读且地址未被清零。CPU、I/O、OOM、锁和 syscall 不保留会产生错误字段解释的旧
raw-tracepoint 降级路径；任一必需探针无法加载时必须显式失败。

所有场景共享以下不变量：

- `related_object.pid` 始终是 TGID，`tid` 才是线程 ID；系统级结论用 `scope=system`，不伪造 PID。
- `time_window` 来自 collector 的真实 `ObservationWindow{Start, End, Elapsed}`，不能按名义 1 秒窗口补值。
- 每个报告必须有稳定的 `root_cause_code`，自然语言只负责解释该代码和证据。
- collector 初始化、Poll 或健康读取失败必须进入状态输出，不能解释成“未发现异常”。
- BPF map 只保存有界聚合状态；用户态按真实窗口做差分、检测、归因和符号化。

## 2. 分层数据流

```text
OS 事件
  -> tp_btf / fentry / 必要的稳定 tracepoint
  -> BPF map（按 task/request/device/lock/syscall 聚合）
  -> collector（真实窗口差分 + /proc 补充）
  -> detector（阈值 + sustain + 联合条件）
  -> rca（root_cause_code + evidence_chain）
  -> JSON session / JSONL / YAML / Markdown
```

`internal/collector` 负责加载、挂载和读取；`internal/detector` 只判断信号是否满足；
`internal/rca` 不重新猜测采集事实；`internal/schema` 和 `schemas/*.schema.json` 定义机器接口。

## 3. CPU 与调度

OS 对应关系是“任务被唤醒进入运行队列 -> 等待 CPU -> 被调度运行 -> 切出”。探针使用
`tp_btf/sched_wakeup`、`sched_wakeup_new`、`sched_switch`，直接读取 `task_struct`、TGID 和
`preempt`，避免手写 tracepoint 字段布局。

BPF 以 `(tgid, tid)` 累计 `run_ns/runq_ns/runq_count/ctx`。睡眠唤醒和抢占后重新入队都会
记录 enqueue 时间，因此平均运行队列等待为 `Δrunq_ns / Δrunq_count`，不是除以上下文切换数。
单次连续运行不少于 5 ms 时采样用户栈，并按 `(tgid, tid, stackid)` 聚合。
若任务在探针挂载前已经运行且长期不切出，10 Hz per-CPU CPU-clock perf heartbeat 只为缺失的
`oncpu_start` 补种当前任务；下一次 `sched_switch` 仍负责精确结算。该 heartbeat 的运行次数和
runtime 一并计入 collector health/性能开销。

用户态按 TGID 汇总所有线程的 `process_cpu_cores`，同时保留最高占用 TID：

| 指标 | 含义 |
|---|---|
| `top_thread_cpu_cores` / `cpu_util` | 最热线程占用的 CPU 核数，1.0 约等于一核 |
| `process_cpu_cores` | 同一进程所有线程核数之和，可大于 1 |
| `runq_wait_us` | 按真实入队次数计算的平均运行队列等待 |
| `runq_count` | 本窗口实际入队计数 |
| `user_hot_stack` | 用户函数名，无法符号化时为 `module+offset` |

最热线程或进程总核数任一持续越过 CPU 阈值即可触发。`cpu.compute_hotspot` 表示计算热点；
有显著运行队列等待时使用 `cpu.scheduler_pressure`。上下文切换多本身不是锁证据，不再推断
“锁竞争”；锁归因必须来自同窗的锁报告。

## 4. 块 I/O

OS 对应关系是 block layer request issue 到 complete 的服务时间。探针使用
`tp_btf/block_rq_issue` 与 `tp_btf/block_rq_complete`，用真实 `struct request *` 作为在途 key，
不再用 `dev+sector+rwbs` 合成可能碰撞的 key。

request state 保存设备、总字节、已完成字节和首次 issue 时间。partial completion 只累计完成
字节；确认最终完成后才删除 state、减少 inflight 并结算时延。健康计数公开
`duplicate_issue/completion_miss/map_update_fail/partial_completion/io_error`，测试结束后还要检查 inflight
是否回到 0。
completion 先于 issue 挂载，`startup_boundary_ns` 初始为 0；两者均就绪后才记录单调时钟边界。
边界前被 issue hook 捕获的 request 仍保留 state 以精确配对，但标为 untracked，不污染会话指标。
缺失 state 时，只有非零 `request.start_time_ns >= startup_boundary_ns` 才是可证明的运行期
`completion_miss`；时间戳为 0 的 queue 保守抑制启动歧义，而 post-attach issue 的 map 写失败由
`map_update_fail` 独立暴露。该协议不依赖写于 issue tracepoint 之后的 `io_start_time_ns`，也不用
前两个 Poll 的宽松 baseline 掩盖首个完整窗口的数据丢失。

设备 map 用 `bpf_spin_lock` 串行更新 inflight 与 `queue_depth × duration` 面积。用户态以真实窗口
计算 `avg_queue_depth`，并同时保留窗口结束时的 `queue_depth` gauge。时延直方图的 P99 和最大值
采用 bucket 上界，避免把整个 bucket 当作精确值。

检测先要求 `p99_lat_ms` 持续越过阈值，再分类：`avg_queue_depth >= 16` 才输出
`io.queue_congestion`；否则输出 `io.device_latency`。没有文件路径或 cache miss 证据时，不推断
“热点文件”或“缓存失效”。

## 5. 内存回收与 OOM

direct reclaim 表示分配线程因内存压力同步进入回收路径，是进程贡献证据；PSI 和 vmstat 描述
系统范围压力。BPF 保留 direct-reclaim begin/end 与 kswapd wake，并增加
`tp_btf/mark_victim` 作为权威 OOM 事件；用户态读取 `/proc/pressure/memory`、
`/proc/vmstat`、`/proc/meminfo` 和进程 RSS/fault 的窗口差分。

OOM victim 使用 `mem.oom_victim` 立即触发，不等待 `sustain`。普通 `mem.reclaim_pressure` 必须
同时满足：

1. 系统压力：`MemAvailable < 15%`（或配置阈值）、PSI some >= 10%、PSI full >= 1%、
   direct reclaim >= 10 ms/s 中至少一项；
2. 进程贡献：direct reclaim、匿名 RSS 增长 >= 64 MiB/s、major fault >= 100/s 中至少一项；
3. 联合条件连续满足 `sustain` 个窗口。

单次 kswapd wake、单次 major fault 和“RSS 最大”只可作为辅助信息，不能独立触发或充当因果
证据。`--target-pid` 模式仍读取全局压力，但候选 culprit 只能来自目标进程树；root 和每个已准入
TGID 都绑定进程启动身份：用户态把 `/proc/<pid>/stat` starttime 编码成带最高位标记的 100 Hz
seed，BPF 用量化后的 group leader `start_boottime` 校验（容许 1 tick），首次命中后升级为精确
纳秒身份。因而已被 `/proc` 找到的深层后代无需依赖 16 层祖先遍历；PID 复用时旧 exact/seed
membership 均不会放行不同启动身份。内核侧的有界祖先检查仍负责发现相邻 `/proc` 快照间的
短生命周期子进程并回传精确身份；目标树内无法定位时输出 `scope=system`。

## 6. futex 与内核同步等待

锁场景先从调度语义区分自愿阻塞和抢占：typed `sched_switch` 的 `preempt` 参数用于排除抢占，
`sched_wakeup` 只记录最近唤醒者。`fentry/fexit do_futex` 捕获 `(tgid, uaddr, op)`，将调度等待与
具体 futex 地址关联。

BPF 按 `(tgid, lock_address, stackid, tid)` 聚合等待；用户态再按 `(tgid, lock_address)` 聚合
等待线程数、累计等待、P99、最大等待和 Top waiters。off-CPU state 同时保存线程精确
`start_boottime`；重新上 CPU 时必须匹配 TGID、TID 和该身份，TID 被复用时只清旧 state、不串账。
没有 futex 地址的等待按内核栈归组。

- `lock.futex_contention`：多个线程等待同一非零 `lock_address`；
- `lock.kernel_sync_wait`：默认只在符号化内核栈命中 mutex/rwsem/flock 等同步路径时输出。

`waker_tid` 仅表示唤醒者，不能称为持锁者。`related_object.pid` 是进程 TGID，`tid` 是 Top waiter；
`lock_address` 为可选的锁实例标识。

## 7. syscall 热点

`tp_btf/sys_enter/sys_exit` 在 enter map 保存起点，在 exit 结算 `(tgid, syscall_nr)` 的次数、总耗时、
P99 和最大耗时；起点 map 为 LRU hash，避免退出缺失导致无界占用。仓库内置从 Linux 6.6-era
`x/sys/unix` 定义生成的完整 amd64 与 asm-generic 表；arm64 使用 generic 编号，riscv64 另处理
架构专用 slot。未来内核新增或当前 ABI 不存在的号码仍保留为 `syscall_<nr>` 和 `syscall_nr`，
不能跨 ABI 套用编号。

等待型 syscall（例如 `epoll_wait/poll/futex/nanosleep`）只有高频时才触发，正常长时间阻塞不是
异常；非等待型 syscall 可由高频或累计耗时触发。根因代码为 `syscall.high_frequency` 或
`syscall.high_latency`。`--target-pid` 可过滤目标树，但正式准确率主测试必须使用全局默认产品
配置，不能靠 target 或正例专用阈值抬高结果。

## 8. 输出、生命周期与聚合

- `--format json`：结束时输出唯一一个 `DiagnosticSession`，包含环境、公开阈值、collector 状态、
  `partial` 和聚合后的 `reports[]`；即使无异常也是合法会话，而不是空文件。
- `--format jsonl`：实时逐行输出紧凑 `AnomalyReport`，用于在线消费。
- YAML/Markdown 保持逐报告输出；`--report` 仍生成 Markdown 汇总报告。
- `--allow-partial=false` 是默认值。`all` 先初始化全部五个 collector 再采集；初始化或 Poll 失败
  立即返回非零。仅显式 `--allow-partial` 才可继续，并在 session 中将失败 collector 与
  `partial=true` 写清楚。

collector 健康快照包括 BPF `program_runtime_ns/program_run_count/map_memory_bytes` 和场景健康计数；
health 读取失败、map update 数据丢失或未匹配 I/O completion 会把 collector 置为失败，Markdown
不得把这种零报告写成“未发现异常”。incident
聚合 key 包含 `root_cause_code`，只合并重叠/相邻的同根因窗口；时间断开或根因变化必须保留为
不同 incident。JSON/JSONL 在写出前通过严格 schema 校验，不跳过损坏对象。

`rca-report-compact` 可对合法旧 JSONL 或 `DiagnosticSession` 再做同一 incident 聚合；输入是 session
时会保留 envelope 和 collector 状态。复现脚本可把聚合前 artifact 放在 `outputs/repro/raw/`，但
compact 失败必须非零退出，不能把损坏 raw 文件复制成“最终合法 JSON”。

稳定根因代码全集：

```text
cpu.compute_hotspot       cpu.scheduler_pressure
io.queue_congestion       io.device_latency
mem.reclaim_pressure      mem.oom_victim
lock.futex_contention     lock.kernel_sync_wait
syscall.high_frequency    syscall.high_latency
```

## 9. 限制与维护

- 需要 root 或等价的 `CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN`；部分系统还需调整 memlock。
- 本轮没有真实 cgroup/container 聚合、插件系统或 RISC-V 实机验收；容器只能借助 host PID
  namespace 做宿主级进程归因。
- amd64/arm64 都必须在目标 openKylin 主机完成 clean build、五场景 E2E、30 分钟 all-mode soak
  与性能测试；“能编译”不等于平台已验收。
- CLI、schema、探针、map 或评测口径变化时，同步更新 README、本文、测试文档和技术报告；提交前
  运行 `make docs-check`，示例必须来自可校验 artifact。
