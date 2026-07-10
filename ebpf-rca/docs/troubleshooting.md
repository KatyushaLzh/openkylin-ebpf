# openKylin 实测排查清单

按“硬环境 -> 构建 -> 加载 -> collector 健康 -> 场景证据”排查。当前实现要求 Kernel 6.6+BTF、
typed BTF tracepoint、`fentry/fexit`、per-CPU perf event 和可解析 kallsyms；没有旧 raw-tracepoint 降级路径。

## 0. 先确认硬前提

```bash
uname -r                                      # >= 6.6
test -r /sys/kernel/btf/vmlinux && echo BTF_OK
id                                            # root 或等价 capabilities
go version                                    # >= 1.22
clang --version                               # 建议 >= 12，支持 target bpf
bpftool version
sudo -n bpftool feature probe kernel
```

lock collector preflight 还需要 root 可读取 `/proc/kallsyms` 的非零地址；`kernel.kptr_restrict=0`
最直接。否则工具明确失败，不能把内核锁分类缺失当成健康零报告。I/O 测试目录必须是实际块设备
文件系统：`df -T <path>` 不应显示 tmpfs。

## 1. 构建阶段

### 1.1 `make vmlinux` 失败或 `vmlinux.h` 异常

常见原因是 `/sys/kernel/btf/vmlinux` 不可读、命中 openKylin 的 bpftool wrapper，或内核没有
`CONFIG_DEBUG_INFO_BTF=y`：

```bash
zcat /proc/config.gz 2>/dev/null | rg BTF || rg BTF "/boot/config-$(uname -r)"
cd .. && bash setup_env.sh --no-build
cd ebpf-rca
../.build_deps/bpftool/src/bpftool version
make vmlinux
```

不要手工执行带 `> bpf/vmlinux.h` 的 dump 来试错：重定向会在 bpftool 失败前截断文件。Makefile
使用临时文件校验后替换。

### 1.2 bpf2go/clang 找不到头或 typed prototype

- `bpf/bpf_helpers.h not found`：准备 `libbpf-dev`，或运行顶层 `setup_env.sh --no-build`；
- `vmlinux.h not found`：先 `make vmlinux`；
- `unknown target bpf`：安装带 BPF backend 的 clang/llvm；
- `BPF_PROG` 参数类型不匹配：用当前目标机 BTF 重新 `make vmlinux generate`，不要继续使用来自
  不同内核/架构的临时生成文件。

仓库跟踪 little-endian bpf2go Go/ELF 产物，使 clean clone 可执行 `go test ./...`；平台验收让
第一棵 `HEAD` clean tree 使用已提交产物完成正式验收，第二棵 tree 才做目标机重生成和 unit/build。
两者 hash/diff 只记录 provenance：内核配置/架构改变 CO-RE local BTF 时字节不同是合法结果。

### 1.3 Go module 下载失败

`GOCACHE` 是编译缓存，`GOMODCACHE` 才保存 cilium/ebpf、x/sys 等源码。离线环境可先验证：

```bash
export GOCACHE=/var/tmp/go-cache
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
export GOPROXY=off GOSUMDB=off
go mod download
go test ./...
```

若 `GOPROXY=off` 仍失败，说明 module cache 不完整，需要在获准联网的普通用户环境预热；不要用
sudo 构建导致 root/普通用户 cache 分裂。

### 1.4 apt/dpkg 或 stress-ng 失败

```bash
sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -f install
```

openKylin 的 stress-ng 包可能因 `libipsec-mb0` 版本不匹配而无法安装。运行顶层
`setup_env.sh --no-build`，使用 `../.build_deps/bin/stress-ng`；不要伪造共享库 ABI。

## 2. 加载与生命周期

### 2.1 `operation not permitted`

优先用 root。能力模式至少需要 `CAP_BPF/CAP_PERFMON`，部分内核/配置还需要
`CAP_SYS_ADMIN`；代码会调用 `rlimit.RemoveMemlock()`。沙箱若设置 `no_new_privs`，进程无法在内部
绕过，必须回宿主或允许提权的环境运行。

### 2.2 typed tracepoint 或 fentry 挂载失败

典型错误会直接写明 `tp_btf/...` 或 `fentry/do_futex`。先确认 BTF 中存在目标类型/函数：

```bash
rg -n 'btf_trace_(sched_switch|block_rq_issue|sys_enter|mark_victim)|do_futex' bpf/vmlinux.h
sudo -n ls /sys/kernel/tracing/events/{sched,block,vmscan}
```

若目标内核缺少 typed tracepoint prototype 或 `do_futex` BTF 函数，当前版本不支持该内核；不能
改回手写 tracepoint context 后继续声称指标等价。换用满足硬前提的 Kernel 6.6+ BTF 内核。

### 2.3 all-mode 中一个 collector 失败

默认 `--allow-partial=false`：五个 collector 必须先全部初始化，任一初始化/Poll 失败就非零退出。
这是正确行为，不是“其余场景应该静默继续”。排障时可临时运行：

```bash
sudo -n ./bin/ebpf-rca --scenario all --allow-partial \
  --duration 10s --format json --output /tmp/partial.json
jq '{partial,collectors}' /tmp/partial.json
```

该 session 必须 `partial=true`，失败 collector 有 `state=failed,error=...`；不能进入准确率/性能结果。
单场景不接受 `--allow-partial`。

### 2.4 verifier 只显示摘要

用 `sudo dmesg` 查看内核日志，或在加载选项中临时启用 cilium/ebpf instruction log。先保存完整
错误和目标机 BTF hash，再修改程序；不同内核 verifier 拒绝点可能不同。

## 3. 输出与健康状态

### 3.1 `--format json` 文件运行中为空

这是预期语义：JSON 在正常结束时一次性写出单个 `DiagnosticSession`。用 SIGINT/SIGTERM 让程序
收尾；SIGKILL 无法保证 session。实时观察改用 `--format jsonl`，每行一个紧凑 report。

### 3.2 JSON 有内容但校验失败

```bash
jq . session.json
python3 scripts/validate_report.py session.json
```

不要把多个 pretty JSON 对象拼接为“JSON stream”，也不要跳过损坏文本。顶层 JSON 必须是
`DiagnosticSession`；JSONL 才允许一行一个 `AnomalyReport`。常见失败包括缺 `root_cause_code`、
`elapsed_ms` 与 start/end 不一致、空 evidence、failed collector 却 `partial=false`。

### 3.3 无报告究竟是正常还是采集失败

先查看 `collectors[]`：必须 initialized、正常 stopped、PollCount>0，且没有 error/health_error。
再看健康计数和 BPF runtime/run-count。只有 collector 生命周期完整时 `reports=[]` 才表示本次窗口
未发现异常。

## 4. 各场景排查

### 4.1 CPU：PID/TID 或 runq 指标异常

`pid` 是 TGID，`tid` 是窗口内最热线程；`process_cpu_cores` 是同 TGID 所有线程之和，可超过 1。
`runq_wait_us=runq_ns/runq_count`，不能用 ctx count 代替 enqueue count。CPU 上下文切换多不会单独
产生锁根因；`cpu.scheduler_pressure` 必须有 runq wait/count 证据。

用户热点栈只对单次连续运行 >=5 ms 的切出采样。缺栈不等同于没有 CPU 热点；先检查目标进程
`/proc/<tgid>/maps` 可读和 ELF 符号，再接受 `module+offset` 回退。

### 4.2 I/O：无事件、时延异常或 inflight 不归零

当前使用 typed `block_rq_issue/complete` 和真实 `struct request *`，不要修改手写 context 偏移；旧
“字段 offset 校正”方法已不适用。

```bash
df -T <fio-directory>
fio --name=rca --filename=<real-disk-path> --direct=1 --ioengine=libaio \
  --iodepth=64 --numjobs=4 --rw=randrw --bs=4k --time_based --runtime=30 \
  --output-format=json --output=/tmp/fio.json
jq '.collectors[] | select(.name=="io") | .health' session.json
```

重点检查 `duplicate_issue/completion_miss/map_update_fail/partial_completion`。结束后 5 秒内 inflight
未归零或 `completion_miss!=0` 表示 request 生命周期不完整，该轮不可当成有效“无异常”。
`io.queue_congestion` 还要求时间加权 `avg_queue_depth>=16`；否则高 P99 只应是
`io.device_latency`，不能推断 cache miss 或热点文件。

### 4.3 内存：有 RSS 增长却无报告

这是可能的正确结果。普通内存报告需要“系统压力 + 进程贡献”联合成立并持续满足：查看
MemAvailable、PSI some/full、direct reclaim ms/s，以及进程 direct reclaim、匿名 RSS 增长率或
major fault 率。kswapd wake 或单次 major fault 只是辅助证据。只有 `mark_victim` OOM 事件立即
触发。

target 模式仍使用全局压力，但 culprit 只能来自目标树；若目标树内无因果对象，合法输出是
`scope=system`，不是伪造 target PID。

### 4.4 锁：futex 地址为 0、栈无符号或 waker 误解

非零 `lock_address` 来自 `fentry do_futex`，用户态按锁实例聚合 waiter；地址为 0 的样本只能按
内核同步栈归类。若所有 futex 地址都为 0，先排查 `fentry/fexit do_futex` 是否都成功挂载和 health
计数，而不是从 `sched_wakeup` 猜锁对象。

栈为地址时检查 `/proc/kallsyms` 与 `kernel.kptr_restrict`。`waker_tid` 只是最近唤醒者，任何输出或
讲解都不能把它称为“持锁者”。typed `sched_switch` 已通过 `preempt` 参数排除抢占，不再依赖旧
`prev_state != 0` 的近似解释。

### 4.5 syscall：名称错误、开销高或正常等待误报

探针是 `tp_btf/sys_enter/sys_exit`，不是 `raw_syscalls` context。内置完整表来自 Linux 6.6-era
`x/sys/unix` 定义：amd64 使用自己的编号，arm64 使用 asm-generic，riscv64 再应用架构 slot
覆盖。未来内核新号仍可能显示 `syscall_<nr>` 并保留原号；更新表时必须引用目标 ABI 定义，不能
复制 x86 编号。

`epoll_wait/poll/futex/nanosleep` 等等待型调用只有 calls/s 高才报告，正常长等待不因累计 wall time
触发。开销问题先看 session 的 BPF runtime/run-count 和 start-map 健康计数，再决定是否用
`--target-pid` 做定向诊断；正式准确率主测试仍必须全局默认配置。

## 5. 容器与多架构

容器需 host PID namespace、宿主 BTF 和足够 capability；详见 [docker.md](docker.md)。容器看到
的是宿主内核，所以镜像用户态架构、BPF little-endian 产物和宿主 BTF 必须相容。

“amd64 可编译”不等于 ARM64 已验收。两平台分别运行 `scripts/platform_acceptance.sh`；正式
E2E/soak/accuracy/benchmark 都由消费已提交 bpf2go 产物的 `HEAD` clean tree 承载，第二棵临时树
仅重生成、unit/build 并记录 hash/diff。`checked_in_equals_host_regenerated=false` 本身不是失败；
重生成无法编译/测试才失败。非 openKylin 或 Kernel < 6.6 的运行只能作为开发测试。

## 6. 最小复现信息

报告问题时至少附上：

```bash
uname -a
sha256sum /sys/kernel/btf/vmlinux
git status --short
./bin/ebpf-rca --help
jq '{environment,configuration,partial,collectors}' session.json
```

再附完整 stderr、运行命令、workload 原始日志和 session；不要只贴自然语言汇总或“文件非空”。
