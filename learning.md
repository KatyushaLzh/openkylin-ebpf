# eBPF 学习笔记

> 基于 `ebpf-rca` 项目代码，从 OS 基础知识出发，逐层理解 eBPF。

---

## 1. eBPF 是什么

eBPF = **内核内虚拟机**，完整构成四件套：

| 组件 | 职责 |
|------|------|
| **挂载点**（tracepoint/kprobe） | 接入内核事件流 |
| **沙箱虚拟机**（eBPF 程序） | 在内核态执行逻辑 |
| **map**（共享 KV 存储） | 内核态 ↔ 用户态通信信道 |
| **Verifier**（验证器） | 加载时静态检查，保证安全 |

**不是"轻量 hook"，而是"一段能跑在内核里的受限 C 代码"。**

核心模型：用户态编译 eBPF 字节码 → `bpf()` syscall 注入 → verifier 检查通过 → 挂到内核预定义锚点（tracepoint 等） → 事件触发时执行 → 通过 map 向用户态回传聚合数据。

---

## 2. eBPF 是事件驱动的回调（不是持续运行的后台进程）

类比：**信号 handler 注册模型**。

```
sigaction(SIGALRM, handler)    ↔  link.Tracepoint("sched", "sched_switch", handler)
  时钟中断触发 → handler 执行     ↔  sched_switch 发生 → eBPF handler 执行
  handler return → 回到被中断代码  ↔  eBPF return → 回到调度器
```

区别：
- 信号 handler 跑**用户态**，eBPF 跑**内核态**
- 信号 handler 只能调 async-signal-safe 函数；eBPF 只能调白名单 helper + 受 verifier 约束（本质都是"中断上下文约束"）
- 信号 handler 仅影响本进程；eBPF 一挂就是**系统全局**

**无事件 = 零 CPU 占用。没有"后台轮询"。**

---

## 3. eBPF 如何避免 kernel panic — Verifier

Verifier 在**加载时**（不是编译时）逐指令静态模拟执行，检查：

1. **无死循环** — 循环必须 `#pragma unroll`（编译期展开），跳转只能向前
2. **无越界访问** — 每次内存访问，必须证明指针合法（判空检查、map value 范围内）
3. **无未初始化变量** — 所有寄存器在使用前有确定值
4. **无除零** — 值域追踪，除数可能为 0 的路径直接拒绝

检查不通过 → 程序拒绝加载，**根本不会执行**。

**Verifier 保证的是"内存安全"，不是"逻辑正确"。**
逻辑错误（算错指标、指错进程）不会导致 kernel panic，只会输出错误的诊断结果。

eBPF 能做的：读写 map、算术运算、调白名单 helper。
eBPF 不能做：`malloc`/`free`、调任意内核函数、无界循环、直接访问任意内核内存（必须走 `bpf_probe_read_kernel`）。

---

## 4. eBPF 执行模型：跑在触发者的上下文里

**不是独立内核线程，是串行插入在触发事件的执行路径中。**

```
CPU0 A 进程时间片到了                   CPU1 正在处理 write() syscall
  │                                      │
  ├── sched_switch tracepoint 触发        ├── block_rq_issue tracepoint 触发
  │     → handle_switch() 同步执行         │     → handle_issue() 同步执行
  │     → return                          │     → return
  │     → 调度器继续                       │     → write() 继续
```

- **同步调用**，不是异步中断或信号投递。tracepoint 是内核源码中硬编码的函数调用点
- **run-to-completion**：不允许休眠、无 `mutex_lock`
- 多核之间才真正并发，靠 `__sync_fetch_and_add` 做原子 map 更新

---

## 5. tracepoint：内核自带的"监控探头"

内核开发者在关键位置埋的标记点，平时零开销（不存在），激活后才执行回调。

```c
// 内核源码（kernel/sched/core.c），不是 eBPF
void __schedule(void) {
    // ...
    trace_sched_switch(prev, next);   // ← tracepoint 埋点
}
```

不是 eBPF 特有的。内核本来就埋了几百个这样的点。eBPF 只是提供了一种向这些点注册回调函数的机制。

---

## 6. BPF map：内核与用户态的通信信道

**不是 mmap 共享内存。** 内核单向拥有内存，两边访问方式不对称：

| | 内核态 eBPF | 用户态 Go |
|---|---|---|
| 访问方式 | **直接指针解引用** `st->run_ns += delta` | **bpf() syscall**（cilium/ebpf 库封装） |
| 速度 | 零拷贝，几十个周期 | 走 syscall，有 copy_from/to_user 开销 |
| 为什么安全 | verifier 已证明指针在 map value 范围内 | N/A（本来就跑用户态） |

**核心设计**：快的那边（eBPF，每秒触发几万次）用直接指针；慢的那边（用户态，每秒只读一次）走 syscall。各取所需。

ebpf-rca CPU 场景的三个 map（`cpu.bpf.c:27-48`）：

```c
oncpu_start   // tid → 上 CPU 的时间戳         (HASH, 16384 entries)
wakeup_ts     // tid → 被唤醒入队的时间戳      (HASH, 16384 entries)
stats         // tid → {run_ns, runq_ns, ctx}  (HASH, 16384 entries)
```

---

## 7. CPU 开销的真实情况

eBPF 的 CPU 开销 = **单次代价 × 触发频率**。

- 正常：无事件 = 无指令执行 = 零 CPU
- 触发：每次 `handle_switch` 约几十到一百周期（几次哈希查找 + 整数加法），上下文切换本身几千周期
- 开销可控：因为没有 per-event 上送到用户态（没有 `copy_to_user`）
- syscall 场景（`raw_syscalls`）是开销最高的：每次 syscall 触发两次 eBPF，一秒几万次

---

## 8. eBPF vs Timer 采样：拍照 vs 录像

| | Timer 采样 | eBPF |
|---|---|---|
| 原理 | 定时快照（如每 10ms 读 `/proc`） | 每事件实时记录 |
| 短脉冲（1ms 延迟尖刺） | 大概率漏掉 | 一个不漏 |
| 分布信息（P99） | 不可见 | 直方图完整 |
| 开销 | 低 | 高频场景需聚合降开销 |

ebpf-rca 的内存场景刻意混合使用：
- eBPF 抓直接回收事件（偶发但致命，timer 拍不到）
- `/proc/meminfo` 读可用内存（低频变化，不值得写 eBPF）

选择原则：
- 事件稀疏 + 需要完整性 → eBPF 挂载
- 事件高频 → eBPF 内核态聚合，不上送每条事件
- 本身就是常量 → 直接读 `/proc`，不用 eBPF

---

## 9. ebpf-rca 完整调用链（CPU 场景）

### 阶段一：加载（一次性）

```
Go: NewCPUCollector()
  └─ bpf() syscall → 内核 verifier 静态检查字节码
  └─ 创建 3 个 map（oncpu_start, wakeup_ts, stats）
  └─ link.Tracepoint("sched", "sched_switch", handleSwitch)
  └─ link.Tracepoint("sched", "sched_wakeup", handleWakeup)
```

### 阶段二：内核事件触发（持续，每切换一次触发一次）

```
sched_switch 发生
  └─ handle_switch:
       prev 切出: run_ns 累加, ctx++（记录进程名）
       next 上 CPU: runq_ns 累加（结算排队时间）
       → 只做 O(1) 聚合，不判断，不发消息
```

### 阶段三：用户态采样（每秒）

```
Go: time.Ticker 触发
  └─ Poll(1s): 遍历 stats map → 差分 → 算 cpu_util / ctx_per_min / runq_wait
  └─ Detect: 阈值(0.9) + 连续窗口(3)判定异常
  └─ BuildCPUReport: 规则分类根因 + 组装证据链
  └─ output: JSON/YAML/Markdown
```

### 阶段四：卸载

```
Ctrl-C → defer col.Close()
  └─ link.Close() → 从 tracepoint 摘除
  └─ objs.Close() → 释放 map 和程序 fd
```

---

## 10. Map 共享、原子性与统计偏差边界

**Map 共享不是缺陷，是内核态聚合的自然选择。** eBPF 程序在事件路径里执行，必须用一个所有 CPU 都能访问的 map 把同一对象的统计累加起来，否则用户态每个窗口要枚举每 CPU 副本再手动归并。

当前 `ebpf-rca` 使用的是普通 `BPF_MAP_TYPE_HASH`，不是 per-CPU map：

| 场景 | 共享 key | 共享 value |
|------|----------|------------|
| CPU | `tid` | `run_ns / runq_ns / ctx / comm` |
| I/O | `dev` | `count / total_lat_ns / max_lat_ns / inflight / slots` |
| 内存 | `pid/tgid` | `direct_reclaim_count / direct_reclaim_ns / comm` |
| 锁 | `tid` | `offcpu_ns / offcpu_count / max_offcpu_ns / last_waker / stackid` |
| syscall | `(pid, syscall_nr)` | `count / total_ns / max_ns / comm` |

但要精确地区分两件事：

1. **共享 map 负责聚合位置**：所有 CPU 都把同一对象写到同一个 value。
2. **原子操作负责并发写正确性**：只有使用 `__sync_fetch_and_add` 的字段才有原子加保障。

项目里的原子性现状：

| 文件 | 使用原子加的字段 | 普通写/普通加的字段 |
|------|------------------|---------------------|
| `block.bpf.c` | `inflight/count/total_lat_ns/bytes/slots` | `max_lat_ns` 是 best-effort 最大值 |
| `syscall.bpf.c` | `count/total_ns` | `max_ns` 是 best-effort 最大值 |
| `mem.bpf.c` | `kswapd_wakes` | `direct_reclaim_count/direct_reclaim_ns` 普通加 |
| `cpu.bpf.c` | 无 | `run_ns/runq_ns/ctx` 普通加 |
| `lock.bpf.c` | 无 | `offcpu_ns/offcpu_count/max_offcpu_ns` 普通加 |

所以更准确的判断是：当前设计接受小概率统计偏差，尤其是 `max_*` 这类 gauge 可能被并发覆盖；I/O/syscall 的主要累计字段用原子加兜底，CPU/lock/mem 更多依赖事件语义降低冲突概率。

真正的 per-CPU map 是 `BPF_MAP_TYPE_PERCPU_HASH`：每个 CPU 有独立 value，写入时通常不需要跨 CPU 原子竞争。但它不会让用户态“自动得到合并后的一个 value”。用户态读取时通常拿到每 CPU value 数组，再自己求和、取最大值或做直方图合并。代价是读路径和合并逻辑更复杂，收益是高频写路径更低竞争。

本项目选择普通共享 hash map 的工程含义：

- 代码简单，用户态 `Poll()` 直接读一个 value。
- 适合比赛原型和低到中等负载诊断。
- 对 `count/total` 类累计值，热点场景最好使用原子加或 per-CPU map。
- 对 `max` 类字段，即使用原子加也不够，需要 CAS 循环或接受 best-effort。

## 11. 五个异常场景解析（从 CSAPP 级 OS 知识出发）

前提：你已经理解上下文切换、缺页、`read()`/`write()` 系统调用、`mutex_lock` 阻塞等待。下面每个场景只补一个关键内核事实。

### 11.1 CPU 异常占用 / 调度延迟

| 已知 OS 概念 | 补充事实 | eBPF 记录什么 | 判定条件 |
|--------------|----------|---------------|----------|
| 线程在 CPU 上运行，时间片到或阻塞时被切走 | `sched_switch` 暴露 prev/next，`sched_wakeup` 暴露被唤醒入队 | `run_ns` 运行时间、`runq_ns` 排队等待、`ctx` 切换次数 | `CPUUtil >= threshold` 连续 `sustain` 窗口 |

内核侧模型：

```
sched_wakeup:
  wakeup_ts[tid] = now

sched_switch:
  prev 被切出:
    run_ns += now - oncpu_start[prev]
    ctx++
  next 上 CPU:
    oncpu_start[next] = now
    runq_ns += now - wakeup_ts[next]
```

用户态每个窗口做差分：

```
CPUUtil    = delta(run_ns) / interval_ns
CtxPerMin  = delta(ctx) / interval_minutes
RunqWaitUs = delta(runq_ns) / delta(ctx) / 1000
```

对应代码：`cpu.bpf.c` 的 `handle_switch` / `handle_wakeup`，Go 侧是 `collector.go`。

### 11.2 I/O 延迟抖动 / 阻塞等待

唯一需要补充的事实：块层请求有两个稳定事件。

| tracepoint | 含义 |
|------------|------|
| `block:block_rq_issue` | 请求下发到块设备队列/驱动 |
| `block:block_rq_complete` | 设备报告请求完成 |

二者时间差就是一次块 I/O 的完成延迟。eBPF 在 issue 时按 `(dev, sector)` 存时间戳，complete 时配对结算。

| 记录的数据 | 推导指标 | 判定条件 |
|------------|----------|----------|
| 完成请求数 `count` | `IOPS = delta(count) / interval` | `P99LatMs >= threshold` 连续 `sustain` 窗口 |
| 累计延迟 `total_lat_ns` | 平均延迟 | |
| log2 延迟直方图 `slots` | P99 延迟估计 | |
| `inflight` | 队列深度 | |
| `bytes` | 吞吐 | |

`inflight = issue - complete`，就是当前在途请求数，近似反映设备队列压力。P99 用 log2 桶估计，不是保存每次请求的原始延迟。

对应代码：`block.bpf.c` 的 `handle_issue` / `handle_complete`，Go 侧是 `io.go`。

### 11.3 内存抖动 / OOM 风险

你已知：缺页是访问虚拟页时发现没有可用物理页映射，内核现场处理。

需要补充的事实：物理内存紧张时，内核有两类回收路径。

| 回收方式 | 谁执行 | 进程感知 |
|----------|--------|----------|
| 后台回收 | `kswapd` 内核线程 | 业务进程通常无直接阻塞 |
| 直接回收 | 申请内存的业务进程自己执行 | 业务进程被卡住，尾延迟升高 |

eBPF 盯直接回收：

```
mm_vmscan_direct_reclaim_begin:
  start[pid] = now

mm_vmscan_direct_reclaim_end:
  direct_reclaim_count++
  direct_reclaim_ns += now - start[pid]

mm_vmscan_kswapd_wake:
  kswapd_wakes++
```

为什么 direct reclaim 是强信号：它说明“想要内存的线程拿不到足够空闲页，只能自己同步回收”。这不是单纯低水位，而是已经进入业务路径的阻塞成本。

当前 detector 的触发条件是系统级的：

```
MemAvailablePct < threshold
连续 sustain 窗口
```

触发后 `pickCulprit()` 才从 `snap.Procs` 里选主要贡献者：优先 direct reclaim 次数，其次 major fault。major/minor fault 不是 eBPF 采集，而是 Go 侧低频读取 `/proc/<pid>/stat` 差分；`MemAvailable` 来自 `/proc/meminfo`。

对应代码：`mem.bpf.c` 的 `handle_direct_begin` / `handle_direct_end` / `handle_kswapd_wake`，Go 侧是 `mem.go`。

### 11.4 锁竞争 / off-CPU 阻塞

你已知：`mutex_lock` 拿不到锁，线程会睡眠，等持锁者释放后被唤醒。

需要补充的事实：`sched_switch` 的 `prev_state` 区分“被抢占”和“主动阻塞”。

| `prev_state` | 含义 |
|--------------|------|
| `0` / `TASK_RUNNING` | 仍可运行，通常是被抢占或让出 CPU |
| 非 0 | 进入睡眠/阻塞状态，可能在等锁、I/O、条件变量等 |

eBPF 逻辑：

```
sched_switch, prev_state != 0:
  offcpu_start[prev] = { now, stackid }

sched_switch, next 上 CPU:
  dur = now - offcpu_start[next]
  lock_stats[next].offcpu_ns += dur
  lock_stats[next].offcpu_count++

sched_wakeup:
  lock_stats[wakee].last_waker = current_tid
```

Go 侧拿到三类证据：

| 数据 | 含义 |
|------|------|
| `offcpu_ns` 窗口增量 | 阻塞睡眠了多久 |
| `stackid` + `/proc/kallsyms` | 阻塞点栈，RCA 用 `futex/mutex/rwsem` 等符号判断是否像锁 |
| `last_waker` | 最近唤醒该线程的人，疑似释放锁或满足条件的一方 |

注意：当前 detector 只看 `OffcpuRatio >= threshold` 连续窗口；是否归类为“锁竞争”，是在 `rca.BuildLockReport()` 里通过阻塞栈符号二次判断。没有命中锁符号时，报告会降级为“长时间阻塞等待”。

对应代码：`lock.bpf.c` 的 `handle_switch` / `handle_wakeup`，Go 侧是 `lock.go`。

### 11.5 系统调用热点

你已知：`read()`/`write()`/`fsync()` 等 syscall 是用户态陷入内核的边界。

eBPF 使用通用 raw syscall tracepoint：

```
raw_syscalls:sys_enter:
  start[tid] = { now, syscall_nr }

raw_syscalls:sys_exit:
  dur = now - start[tid].ts
  syscall_stats[(tgid, nr)].count++
  syscall_stats[(tgid, nr)].total_ns += dur
  syscall_stats[(tgid, nr)].max_ns = max(max_ns, dur)  // best-effort
```

用户态窗口指标：

```
CallsPerSec    = delta(count) / interval
AvgLatUs       = delta(total_ns) / delta(count) / 1000
TotalMsPerSec  = delta(total_ns) / interval / 1e6
```

当前 detector 的触发条件是二选一：

```
CallsPerSec >= threshold       // 默认 10000 次/秒
或 TotalMsPerSec >= 300         // 单个 syscall 每秒累计占用超过 300ms
```

`AvgLatUs >= 1000` 不是触发条件，而是 RCA 分类条件：触发后如果平均单次耗时超过 1ms，就报告为“高耗时系统调用热点”；否则报告为“高频系统调用热点”。

对应代码：`syscall.bpf.c` 的 `handle_enter` / `handle_exit`，Go 侧是 `syscall.go`。

### 11.6 五场景对比总表

| 场景 | OS 核心机制 | 挂载点 | eBPF 记录什么 | 判定手段 |
|------|-------------|--------|---------------|----------|
| CPU | 调度切换 | `sched_switch` + `sched_wakeup` | 运行时间、排队时间、切换次数 | 单核占用率持续超阈值 |
| I/O | 块层请求生命周期 | `block_rq_issue` + `block_rq_complete` | 请求延迟、队列深度、直方图 | P99 延迟持续超阈值 |
| 内存 | 直接回收 / 后台回收 | `mm_vmscan_direct_reclaim_begin/end` + `mm_vmscan_kswapd_wake` | direct reclaim 次数/耗时、kswapd 唤醒 | 可用内存占比持续低于阈值 |
| 锁 | 阻塞型 off-CPU | `sched_switch` + `sched_wakeup` | off-CPU 时长、阻塞栈、唤醒者 | off-CPU 比例持续超阈值，RCA 再看锁栈 |
| syscall | syscall 入口/出口 | `raw_syscalls:sys_enter/exit` | 次数、总耗时、最大耗时 | 高频或累计耗时持续超阈值 |

共性：内核态只做聚合计数，用户态按窗口差分，再由 detector 判定持续异常。锁场景额外调用 `bpf_get_stackid` 抓阻塞栈，这是相对更贵的操作，但只在阻塞切出路径执行。

### 11.7 一次 `write()` 可能触发多个探针

```
用户态 write(fd, buf, len)
         |
         v
raw_syscalls:sys_enter         -> syscall 热点开始计时
         |
         | 可能缺页 / 分配页
         |   -> direct_reclaim_begin/end
         |
         | 可能提交块 I/O
         |   -> block_rq_issue
         |   -> block_rq_complete
         |
         | 可能等锁 / 等 I/O 睡眠
         |   -> sched_switch(prev_state != 0)
         |   -> sched_wakeup
         |
         | 调度切换穿插发生
         |   -> sched_switch 统计 CPU run_ns / ctx
         |
raw_syscalls:sys_exit          -> syscall 热点结算耗时
         |
         v
返回用户态
```

这些探针彼此独立，不共享逻辑，只是从不同内核层面观察同一次业务行为。最终 RCA 依靠 evidence chain 把 CPU、I/O、内存、锁、syscall 的局部证据组织成根因判断。

## 12. main.go：用户态总控逻辑

`cmd/ebpf-rca/main.go` 本身不直接分析内核事件，它是 **orchestrator**：

```
命令行参数
  → 选择场景 runXXX
  → 初始化 collector / detector
  → 预热 Poll 建立差分基线
  → runLoop 周期采样
  → collector.Poll → detector.Detect → rca.BuildXXXReport → handler
  → Ctrl-C / SIGTERM / duration 到期退出
```

### 参数解析

`main()` 先解析：

| 参数 | 含义 |
|------|------|
| `--scenario` | 选择 cpu/io/mem/lock/syscall/all |
| `--interval` | 采样窗口大小 |
| `--threshold` | 异常阈值；为 0 时使用场景默认值 |
| `--sustain` | 连续多少个窗口异常才触发 |
| `--duration` | 总运行时间；0 表示直到 Ctrl-C |
| `--format` / `--output` / `--report` | 控制流式输出或汇总报告 |

`thresholdFor()` 给每类场景默认阈值。syscall 场景默认是 `10000` 次/秒。

### handler：每条诊断报告如何处理

`handler` 的类型是：

```go
type handler func(schema.AnomalyReport)
```

它处理的是一条完整 `AnomalyReport`，不是单条 evidence：

- 未设置 `--report`：立刻用 `output.Write` 按 JSON/YAML/Markdown 输出
- 设置 `--report`：先 `agg.Add(r)` 聚合，程序退出后统一 `agg.Render`

### context：把退出信号变成取消事件

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
```

含义：收到 Ctrl-C(`SIGINT`) 或 `SIGTERM` 时，`ctx.Done()` 会被关闭。

`runLoop` 中：

```go
select {
case <-ctx.Done():
    return
case <-deadline:
    return
case now := <-ticker.C:
    tick(now)
}
```

所以退出路径是：信号到达 → context 取消 → 采样循环返回 → `defer col.Close()` 卸载 eBPF 资源。

### runSyscall 执行路径

系统调用性能分析对应：

```go
case "syscall":
    err = runSyscall(ctx, cfg, h)
```

`runSyscall` 做四件事：

1. `collector.NewSyscallCollector()`：加载并挂载 syscall eBPF 程序
2. `detector.NewSyscallDetector(cfg.threshold, cfg.sustain)`：创建连续窗口检测器
3. `col.Poll(cfg.interval)`：预热一次，建立窗口差分基线
4. `runLoop(...)`：每个窗口执行采样、检测、RCA、输出

核心循环：

```go
samples, err := col.Poll(cfg.interval)
for _, sig := range det.Detect(samples, now) {
    h(rca.BuildSyscallReport(sig))
}
```

### 窗口差分在 collector 中完成

BPF map 保存的是累计值，例如 syscall 场景的：

```
Count   = 累计调用次数
TotalNs = 累计耗时
MaxNs   = 历史最大单次耗时
```

collector 保存上一轮 `prev`。每次 `Poll` 读取当前 `cur` 后计算：

```go
dCount := cur.Count - prev.Count
dTotal := cur.TotalNs - prev.TotalNs
```

再换算成窗口指标：

```
calls_per_sec   = dCount / interval
avg_lat_us      = dTotal / dCount
total_ms_per_sec = dTotal / interval
```

因此分工是：

| 模块 | 职责 |
|------|------|
| collector | 读 BPF map，做窗口差分，生成窗口样本 |
| detector | 阈值 + 连续窗口判定异常是否成立 |
| rca | 根据异常信号和指标做规则化根因分类 |
| output/report | 输出单条报告或汇总报告 |

### 为什么 runLoop 前要先 Poll 一次

第一次 `Poll` 的结果被丢弃：

```go
_, _ = col.Poll(cfg.interval)
```

它的作用不是诊断，而是记录当前累计值到 `prev`。

如果不预热，第一次正式采样时 `prev` 为空，collector 会把 eBPF 程序加载以来的全部累计值当作第一个窗口增量，导致第一次窗口不干净。

预热后的时间线：

```
t0: eBPF 已挂载，map 开始累计
t0: Poll() 只建立 prev，丢弃样本
t1: ticker 触发，Poll() 得到 t0~t1 的差分
t2: ticker 触发，Poll() 得到 t1~t2 的差分
```

注意：当前速率计算使用传入的 `cfg.interval`，不是实测的 `now - lastPoll`。如果 Go 调度或系统负载导致 tick 延迟，速率会有轻微误差；更严谨的实现应记录真实采样时间差。

---

## 13. 关键设计原则

**两态分离**：内核态只做机械计数（零判断、零分支），全部"智力"（算指标、判阈值、定根因）在每秒 1 次的用户态循环。

**注入是一次性的，不是每次 syscall 都注入**：Go 启动时一次性把字节码加载、挂载好，之后就驻留在内核事件链上。后续每次 tracepoint 触发，直接函数指针跳转到 eBPF 程序，不经过 syscall。
