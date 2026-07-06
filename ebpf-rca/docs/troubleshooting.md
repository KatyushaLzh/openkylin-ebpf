# openKylin 实测踩坑排查清单

按「构建 → 加载/挂载 → 各场景运行 → 容器/多架构」顺序排查。每条给出**症状 / 原因 / 解法**。
先跑下面的"环境自检"，多数问题能提前发现。

## 0. 环境自检（上手先跑这几条）

```bash
uname -r                                   # 内核 ≥ 6.6
ls -l /sys/kernel/btf/vmlinux              # 存在 = 内核启用 BTF（CO-RE 前提）
cat /proc/sys/kernel/perf_event_paranoid   # 建议 <= 1
cat /proc/sys/kernel/kptr_restrict         # 建议 0（栈符号化需要）
id                                         # 确认 root；或具备 CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN
which clang llvm-strip go                  # 构建工具齐全
./.build_deps/bpftool/src/bpftool version
./.build_deps/bin/stress-ng --version
go version                                 # >= 1.22
```

---

## 1. 构建阶段

### 1.1 `make vmlinux` 失败 / `bpf/vmlinux.h` 为空
- 症状：`bpftool: command not found` 或 dump 出来是空文件。
- 原因：未装真正的 bpftool、命中了 openKylin 的 `/usr/sbin/bpftool` wrapper，或
  `/sys/kernel/btf/vmlinux` 不存在（内核未启用 `CONFIG_DEBUG_INFO_BTF`）。
- 解法：
  ```bash
  # 在仓库根目录
  bash setup_env.sh --no-build
  ./.build_deps/bpftool/src/bpftool version
  cd ebpf-rca && make vmlinux

  zcat /proc/config.gz 2>/dev/null | grep BTF || grep BTF /boot/config-$(uname -r)
  # 应看到 CONFIG_DEBUG_INFO_BTF=y；若无，需换启用 BTF 的内核
  ```
  不要直接试错执行 `bpftool ... > bpf/vmlinux.h`，失败时 shell 重定向会先截断目标文件；
  `setup_env.sh` 和 `make vmlinux` 已改成临时文件校验后再替换。

### 1.2 `go generate` / bpf2go 报错找不到头文件
- 症状：`fatal error: 'bpf/bpf_helpers.h' file not found` 或 `vmlinux.h not found`。
- 原因：未装 `libbpf-dev`；或未先 `make vmlinux` 生成 `bpf/vmlinux.h`。
- 解法：优先在仓库根目录运行 `bash setup_env.sh --no-build`；它会在系统包不可用时从 gitee
  准备 libbpf 头文件软链。也可以手动 `sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y libbpf-dev`，
  再 `make vmlinux`，最后 `make build`。
  确认 `gen.go` 的 `-I../../bpf` 能找到 `vmlinux.h`，系统 `/usr/include/bpf/` 提供 libbpf 头。

### 1.3 clang 编译 .bpf.c 报错
- 症状：`unknown target 'bpf'` 或重定义。
- 原因：clang 版本过旧（建议 ≥ 12），或缺 `-target bpf`（gen.go 已用 `-target bpfel`）。
- 解法：`sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y clang llvm`；确认 clang ≥ 12（`clang --version`）。

### 1.4 `go build` 拉取依赖失败
- 症状：`dial tcp ... timeout`（cilium/ebpf、yaml.v3）。
- 解法：配置 GOPROXY：`go env -w GOPROXY=https://goproxy.cn,direct`，再 `go mod tidy`。

### 1.5 apt/dpkg 处于半配置状态
- 症状：`dpkg -l` 中出现 `iF iperf3`，或 apt 提示需要先运行 `dpkg --configure -a`。
- 原因：安装依赖时触发 debconf 交互，非交互环境下包已解包但配置失败。
- 解法：
  ```bash
  sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -f install
  ```
  如果 `sudo -n` 提示需要密码，先在 VM 终端执行 `sudo -v`，或切到 root shell。

### 1.6 `stress-ng` apt 安装失败
- 症状：`stress-ng` 依赖 `libipsec-mb0`，但 openKylin 源里只有 `libipsec-mb1`。
- 原因：仓库依赖关系与当前发行版库版本不匹配。
- 解法：
  ```bash
  # 在仓库根目录
  bash setup_env.sh --no-build
  ./.build_deps/bin/stress-ng --cpu 1 --timeout 1s --metrics-brief
  ```
  不要手工伪造 `libipsec-mb0`；这是 ABI 风险，不值得带进测试环境。

---

## 2. 加载 / 挂载阶段

### 2.1 权限错误
- 症状：`operation not permitted` / `permission denied`，启动即失败。
- 解法：用 `sudo` 运行；或赋能力：
  ```bash
  sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ./bin/ebpf-rca
  ```

### 2.2 RLIMIT_MEMLOCK / 内存锁定
- 症状：`failed to create map: operation not permitted`。
- 说明：代码已调用 `rlimit.RemoveMemlock()`，正常无需手动处理；若仍报错，确认以 root 运行。

### 2.3 运行时 BTF 缺失
- 症状：`field ... : not found` / `BTF ... not found`。
- 原因：运行内核无 BTF。解法同 1.1，需启用 BTF 的内核。

### 2.4 tracepoint 不存在 / 挂载失败
- 症状：`attach <tracepoint>: no such file or directory`。
- 排查：列出可用 tracepoint，确认名称：
  ```bash
  sudo ls /sys/kernel/tracing/events/sched/        # sched_switch, sched_wakeup
  sudo ls /sys/kernel/tracing/events/block/        # block_rq_issue, block_rq_complete
  sudo ls /sys/kernel/tracing/events/vmscan/       # mm_vmscan_direct_reclaim_begin/end, mm_vmscan_kswapd_wake
  sudo ls /sys/kernel/tracing/events/raw_syscalls/ # sys_enter, sys_exit
  ```
- 说明：`--scenario all` 对单个场景挂载失败会**告警跳过**，不影响其余场景。

### 2.5 想看 verifier 详细报错
- 做法：临时在加载处打印完整错误（`fmt.Printf("%+v", err)`），或给 `loadXObjects` 传入
  `&ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction}}` 获取逐指令日志；
  也可 `sudo dmesg | tail` 看内核侧拒绝原因。

---

## 3. 各场景运行 / 正确性

### 3.1 【重点】② I/O 场景指标异常 —— tracepoint 字段偏移
- 症状：P99/IOPS/设备名明显不对（如 dev 乱码、时延为 0 或天文数字）。
- 原因：`block_rq_issue/complete` 的字段布局随内核版本变化，`block.bpf.c` 中手写的结构体偏移与本机不符。
- 解法：用 format 文件核对并修正结构体：
  ```bash
  sudo cat /sys/kernel/tracing/events/block/block_rq_issue/format
  sudo cat /sys/kernel/tracing/events/block/block_rq_complete/format
  ```
  按 `offset:` 调整 `struct block_rq_issue_tp / block_rq_complete_tp` 中各字段（尤其 `dev` 后到 `sector` 的对齐填充、`bytes` 字段是否存在）。

### 3.2 【重点】② I/O 注入了 fio 却无任何 I/O 异常
- 症状：跑 `repro_io.sh` 但工具无输出。
- 原因：`/tmp` 是 **tmpfs（内存文件系统）**，fio 读写不经过块设备层，自然无 `block_rq` 事件。
- 解法：把 fio 的 `--filename` 指向**真实磁盘**上的路径（如仓库目录下 `./fio-test.img`），
  并确认该路径所在分区是块设备：`df -T .`（类型不应为 tmpfs/overlay）。

### 3.3 ④ 锁竞争：阻塞栈显示地址而非函数名
- 症状：`evidence_chain` 里 stack 是 `0x...` 而非 `futex_wait_queue` 这类符号。
- 原因：`/proc/kallsyms` 地址被屏蔽。
- 解法：`sudo sysctl -w kernel.kptr_restrict=0`，并确保 root 运行。

### 3.4 ④ 锁竞争：未识别为"锁竞争"而是"长阻塞"
- 原因：阻塞栈未命中 futex/mutex 等关键字（不同内核函数名略有差异）。
- 解法：实测看到的实际栈帧名，按需在 `internal/rca/lock.go` 的 `lockSymHints` 增补（如 `osq_lock`、`rwsem_down`）。

### 3.5 ④ prev_state 语义
- 说明：代码以 `prev_state != 0` 判定"阻塞型切出"。个别内核对 state 有 `TASK_REPORT` 高位编码，
  一般 `!= 0` 仍正确；若发现大量误计，核对 `sched_switch/format` 的 `prev_state` 字段类型与取值。

### 3.6 ③ 内存：无 direct reclaim 事件
- 症状：注入内存压力但 `direct_reclaim_count` 始终为 0。
- 原因：系统内存充裕，未触发"直接回收"（只走了后台 kswapd）。
- 解法：`stress-ng --vm-bytes` 调大（如 90%）或减小可用内存；也可降低 `--threshold`（可用内存下限）触发。

### 3.7 ⑤ syscall：名称不对（尤其 ARM64）
- 症状：syscall 名显示为 `syscall_<nr>` 或张冠李戴。
- 原因：syscall 号随架构而异；`internal/syscalls` 内置 amd64 表与 asm-generic 表为常见子集。
- 解法：缺失项按内核头补全：amd64 见 `/usr/include/asm/unistd_64.h`，
  arm64/riscv 见 `asm-generic/unistd.h`；把缺的号→名补进对应 map。

### 3.8 ⑤ syscall：开销偏高
- 说明：`raw_syscalls` 触发极频繁，是预期内最高开销场景。演示/评测可只单独跑、缩短时长；
  生产可加 target_pid 过滤（见 design.md 扩展点）只观测目标进程。

### 3.9 误报 / 漏报调参
- 误报多：增大 `--threshold` 或 `--sustain`（连续窗口数）。
- 漏报：减小阈值或 `--sustain`，或增大 `--interval` 让信号更稳定。
- 空载自检：不注入负载时跑 60s，应**无**告警。

### 3.10 stress-ng 缺少某 stressor
- 症状：`stress-ng: unrecognized option '--mutex'`。
- 解法：在仓库根目录运行 `bash setup_env.sh --no-build` 准备本地源码版；
  当前测试脚本会优先使用 `../.build_deps/bin/stress-ng`。
  若仍需系统版本，可升级 stress-ng；锁场景也会在 `--mutex` 不可用时退到 `--futex`。

---

## 4. 容器 / 多架构

- 容器内加载失败：确认 `--privileged` 或 `--cap-add SYS_ADMIN,BPF,PERFMON`，并挂载
  `/sys/kernel/btf`、`/sys/kernel/debug`，加 `--pid=host`。详见 [docker.md](docker.md)。
- 多架构：每个架构都需各自的内核 BTF（在目标机生成对应 `vmlinux.h` 再构建）；
  syscall 名表按架构选择（代码已按 `runtime.GOARCH` 区分）。
- bpf2go 目标字节序：x86_64/arm64/riscv64 均为小端，使用 `-target bpfel` 正确；无需改动。

---

## 5. 一键自检脚本片段（可贴入复现前）

```bash
[ -e /sys/kernel/btf/vmlinux ] && echo "BTF OK" || echo "BTF 缺失!"
[ "$(id -u)" = 0 ] && echo "root OK" || echo "请用 sudo"
df -T . | awk 'NR==2{print "当前分区类型:",$2}'   # 确认非 tmpfs（影响 I/O 场景）
```
