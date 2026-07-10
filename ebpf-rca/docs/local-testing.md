# 本地 E2E 测试系统

本地 E2E 的核心判定不是“出现了文本”，而是：严格 `DiagnosticSession` 中存在同时匹配异常类型、
`root_cause_code` 和独立 workload 对象 oracle 的报告，并且没有额外错误报告。

## 1. 运行模型

`scripts/test_local.sh` 每次场景测试执行：

```text
准备 workload / 启动 strict all-mode 工具
  -> 独立采样 workload TGID/TID/device oracle
  -> 等待工具结束并写出一个 DiagnosticSession
  -> rca-testcheck 严格解析 schema
  -> 校验 type + code + object + metrics + evidence
```

即使每轮只注入一个场景，工具也固定使用 `--scenario all`、默认阈值/sustain、无
`--target-pid`。因此可以同时发现跨场景误报。任一不匹配的额外报告会让正例检查失败，而不是只
写 warning；负例要求 `reports=[]`。collector/session/ground-truth 失败是基础设施错误，不是 TN。

## 2. 准备

要求 openKylin、Kernel 6.6+、可读 BTF/kallsyms、typed tracepoint/fentry/perf-event 能力和
root/等价 capability。I/O 需要 fio；只有显式附加的 CPU stress 模式需要 stress-ng。正式默认的
CPU、内存、锁和 syscall 主用例统一使用仓库 `rca-testload` 的低交叉标签、对象可校验负载。锁正例
使用显式 CAS + `FUTEX_WAIT_PRIVATE` 状态字，而不是会在 Go runtime 内停车 goroutine 的
`sync.Mutex`；负载直接输出同一个 `uaddr` 和实际 waiter TID，作为独立对象 oracle。

```bash
cd ebpf-rca
make deps
make vmlinux generate
make build test-checker test-load
sudo -n bash scripts/test_local.sh preflight --no-build
```

普通用户先构建，再只对加载阶段使用 sudo，避免 Go cache 分裂。离线环境：

```bash
export GOCACHE=/var/tmp/go-cache
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
export GOPROXY=off GOSUMDB=off
go mod download
make build test-checker test-load
```

## 3. 常用命令

```bash
# CPU + syscall 快速链路
bash scripts/test_local.sh smoke --workload deterministic --duration 15

# 逐个注入五类正式 deterministic 正例；每轮工具仍是 strict all-mode
bash scripts/test_local.sh all --duration 30

# 附加现实压力测试；不替代正式 deterministic oracle 矩阵
bash scripts/test_local.sh all --workload stress --duration 30

# 五类语义负例：idle、正常内存、正常 epoll、普通 I/O 睡眠、低延迟顺序 I/O
bash scripts/test_local.sh negative --duration 15

# --scenario all + --report 的 Markdown 汇总路径
bash scripts/test_local.sh report --workload deterministic --duration 30

# 单个注入场景
bash scripts/test_local.sh scenario --scenario io --duration 30
```

`--no-build` 复用现有二进制；`--out DIR` 指定 artifact；`--io-path PATH` 必须位于真实块设备
文件系统。每个 workload 都在独立 session/process-group 中运行并有 `duration+5s` 的硬超时；中断或
失败会 TERM 后 KILL 整个组，避免内存 worker/fio job 被遗留为孤儿。truth watcher 先绑定 root 的
`/proc/<pid>/stat` starttime；deadline 到期时同一进程实例仍存活会由 checker 直接失败，shell wrapper
再做一次 live/non-zombie 二次检查，不能把 PID reuse 或不完整 oracle 写成成功。
命令返回非零就表示 workload、工具、truth 或 checker 至少一环失败。

## 4. Ground truth 与严格 checker

- CPU：采样 workload 进程树的 TGID/TID，报告 PID 必须是 TGID，Top TID 必须属于该树；
- I/O：用测试文件的设备号建立 oracle，分区/父设备按 checker 规则归一；
- 内存：报告 culprit 必须命中 workload TGID；确实无法定位时仅允许显式 system-scope 用例；
- futex：TGID/TID 必须命中 workload；`lock-oracle.json` 中的显式 futex 地址必须与报告
  `related_object.lock_address` 相等，且至少两个不同 waiter TID 实际在该地址等待；
- syscall：TGID 命中 workload，syscall name/nr 与场景规则一致。

`tests/scenarios.yaml` 为每个用例声明 expected anomaly type、expected root cause code、必需 metrics、
evidence 和数值下限。`rca-testcheck` 使用 `DisallowUnknownFields`，接受一个严格 session 或严格
JSONL；不再接受连续 pretty JSON 对象流，也不会跳过损坏行。

## 5. 多轮准确率

```bash
# 默认每场景 10 轮、deterministic workload（I/O 仍使用 fio）
make accuracy-full

# 快速开发回归，不可作为最终评分数字
python3 scripts/eval_accuracy.py --scenario cpu --repeat 2 \
  --workload deterministic --duration 15 --out outputs/accuracy-cpu

# 只重算已有 check.json；原始失败仍保留
python3 scripts/eval_accuracy.py \
  --from-existing outputs/accuracy/runs --out outputs/accuracy
```

正式结果还要检查 `accuracy_summary.json` 的 `acceptance.coverage_complete` 与
`acceptance.all_targets_met`；“脚本成功生成文件”不代表四项验收阈值通过。

当前默认集合是五类正例加五类语义负例：`idle/normal_mem/normal_epoll/normal_io_sleep/normal_io_seq`。
旧 `idle_cpu/idle_io/idle_lock/idle_syscall` 仅保留为兼容别名，不进入默认主矩阵。每类默认 10 轮；
减少轮数的开发回归不能作为最终评分数字。

统计规则：匹配 type+code+oracle 且无 extra report 才记 TP；缺匹配为 FN；任一 extra report 或
负例报告为 FP。每轮 `run_status.json` 单独记录 tool/workload/truth/health/checker 退出码；前四项非零、
状态文件缺失，或 checker 不能产出 `evaluation_valid=true` 的严格结果时记 `infra_error`。checker 因
正常的 FN/FP 返回非零仍是有效诊断轮次，不能和基础设施故障混为一谈。最终还需输出
macro F1、root-code 正确率与对象 Top-1；Top-1 是 confidence 最高、同分最早的同一报告，不能对
code 与对象分别 any-match。旧的单一“diagnostic accuracy”不能代替这些指标。
其中 `health_rc` 也承载场景完整性后置条件：I/O drain/counter 必须干净；内存负载必须用动态
worker 计划在安全的单 worker 触页速率下跨过 15% MemAvailable 并持续至少 5 秒（或记录真实 OOM
victim）；lock 的显式 futex 地址/TID/wait-wake oracle 必须完整；syscall 实测速率必须达到
`max(10000, 0.8*target)`。futex 地址和注入 syscall 名会原子写入 `ground_truth.json`，随后由主
checker 精确匹配；错地址/错 syscall 报告正常计 FP/FN，而不是 infra_error。

## 6. Artifact 目录

```text
test-results/<timestamp>/
├── env.txt
├── run.log
├── cpu/
│   ├── output.json          # 单个 DiagnosticSession
│   ├── ebpf-rca.stderr
│   ├── workload.log
│   ├── ground_truth.json
│   ├── mem-oracle.json       # mem 用例：跨压/持续窗口或 OOM victim 后置条件
│   ├── lock-oracle.json      # lock 用例：独立 uaddr、waiter TID 与 futex 调用计数
│   ├── syscall-oracle.json   # syscall 用例：read 名称、目标/实测速率
│   ├── run_status.json       # tool/workload/truth/health/checker 分项退出码
│   ├── ground_truth.log
│   ├── check.log
│   └── check.json
└── ...
```

检查 `output.json` 时先看 `partial=false` 和五个 `collectors[]` 生命周期，再看 `reports[]`；空
reports 只有在 collector 都正常时才是有效观测。每轮准确率 artifact 还保留 `eval_command.log`，
用于证明工具没有传 target 或正例专用阈值。

## 7. 平台验收入口

本地短测不能代替平台交付。x86_64 与 ARM64 分别执行：

```bash
bash scripts/platform_acceptance.sh \
  --soak-duration 30m --accuracy-repeat 10 --bench-repeat 5
```

该入口先对 `HEAD` clean snapshot 使用已提交的 bpf2go Go/ELF 产物完成 unit/build；随后同一 archive
的第二棵临时树执行目标机重生成与 unit/build，只把 SHA256、二进制 diff 和 equality flag 作为
provenance 保存，不修改工作区。五类 E2E、30 分钟 all-mode soak 和严格性能配对最终仍在第一棵树
运行。CO-RE object 因本地 BTF/架构产生字节差异不算失败。脚本仍会硬拒绝非 openKylin、
Kernel < 6.6、非 x86_64/ARM64、BTF 缺失或 `outputs/` 之外的未提交项目改动。两架构必须各自产生
bundle。

## 8. 常见失败

- `missing readable /sys/kernel/btf/vmlinux`：换用 Kernel 6.6+BTF，不存在降级路径；
- `attach tp_btf/...` / `fentry/do_futex` / `perf_event_open`：目标内核缺 typed prototype、fentry 或 perf 能力；
- `partial=true` / collector failed：查看 session 中对应 error，默认主测试不允许 partial；
- `empty JSON input`：JSON 只在正常结束写出；不要 SIGKILL，实时观察改用 JSONL；
- I/O 无报告：确认目录非 tmpfs/overlay、fio 为 direct+libaio，并检查 I/O health/inflight；
- 内存无报告：普通异常必须同时有系统压力和进程贡献，单纯 RSS 增长不足；
- 锁初始化失败：确认 `do_futex` fentry/fexit，且 root 能从 `/proc/kallsyms` 读到非零地址；
- 锁无报告：确认同一非零 lock address 在窗口内至少有两个 waiter，不要把单个正常条件变量等待或 waker 推断为竞争/持锁者；
- `sudo ... no new privileges`：只能在宿主或允许提权的环境运行；
- stress-ng 包失败：运行顶层 `setup_env.sh --no-build` 使用本地构建版本。

## 9. 清理

```bash
make test-local-clean
```
