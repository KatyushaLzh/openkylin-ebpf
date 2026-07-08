# 本地 E2E 测试系统

本测试系统用于在 openKylin / Kernel 6.6+ 主机上做端到端校验：注入异常负载，
运行 `ebpf-rca` 采集，再用 `rca-testcheck` 校验 JSON/Markdown 诊断结果。

## 核心模型

测试不是校验某个固定数值，而是校验“信号是否成立”：

- 输出能被解析为 `schema.AnomalyReport`
- `anomaly_type` 与场景匹配
- 关联对象、关键指标、时间窗口、根因、证据链、建议字段完整
- 关键指标存在并满足宽松方向性阈值

这样能避免硬件、调度、磁盘和内存状态差异导致的脆弱测试，同时覆盖比赛评分里的
结构化输出、诊断准确性和证据链一致性。

## 准备

```bash
# 先进入仓库根目录
cd ebpf-rca
make deps
make vmlinux
```

等价地，也可以在仓库根目录执行 `bash setup_env.sh --no-build`。`make deps` 已经转调这个脚本。

需要 root 或可用 `sudo`，并要求 `/sys/kernel/btf/vmlinux` 存在。I/O 场景需要 `fio`，
内存和 stress 模式下的 CPU/锁场景需要 `stress-ng`；deterministic 模式使用仓库内
`cmd/rca-testload` 生成可控 CPU / syscall / flock 负载。
如果 openKylin 的 `stress-ng` 包因 `libipsec-mb0` 依赖缺失无法安装，测试脚本会自动使用
`../.build_deps/bin/stress-ng` 中的源码构建版本。

先用普通用户完成构建，避免 root 和普通用户 Go cache 分裂：

```bash
export GOCACHE=/var/tmp/go-cache
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
export GOPROXY=off GOSUMDB=off
go mod download
make build test-checker test-load
```

自动化环境建议使用非交互 sudo，并用绝对路径调用脚本：

```bash
sudo -n /usr/bin/bash "$PWD/scripts/test_local.sh" preflight --no-build
sudo -n /usr/bin/bash "$PWD/scripts/test_local.sh" all --workload deterministic --duration 30 --no-build
```

`sudo -n` 不会弹密码；如果当前 shell 没有 sudo timestamp 或免密配置，它会立即失败。
此时先在 VM 终端执行一次 `sudo -v`，或配置仅允许该测试脚本的免密规则。
不建议使用 `sudo -E` 依赖环境继承；某些 sudoers 策略会因为未启用 `SETENV` 拒绝执行。

本仓库当前还保留了一个本机复跑 wrapper：

```bash
./out/run-real-ebpf-e2e.sh
```

它会按“离线构建 → 静态检查 → root eBPF E2E”的顺序执行。不要用 `sudo` 直接运行整个
wrapper；脚本内部会在需要加载 eBPF 的阶段调用 `sudo -n /usr/bin/bash ... --no-build`。

## 常用命令

```bash
# 只检查环境，不运行负载
bash scripts/test_local.sh preflight

# 快速烟测：CPU + syscall
bash scripts/test_local.sh smoke --workload deterministic

# 五类正向异常场景
bash scripts/test_local.sh all --workload deterministic

# 空载负向测试，检查基础误报
bash scripts/test_local.sh negative

# 汇总 Markdown 报告测试
bash scripts/test_local.sh report --workload deterministic
```

也可以单独运行某个场景：

```bash
bash scripts/test_local.sh cpu --workload deterministic --duration 20
bash scripts/test_local.sh scenario --scenario io --duration 30
make test-local TEST_DURATION=60
```

## 多轮准确率评测

单轮 `test_local.sh` 用于判断一次注入是否命中。需要形成比赛报告里的“准确率 / 误报率 /
混淆矩阵”时，使用多轮评测脚本：

```bash
# 默认：五类正例 + 四类 idle 负例，每场景 3 轮，stress workload
make accuracy-full

# 快速回归：只跑 CPU，两轮 deterministic workload
python3 scripts/eval_accuracy.py --scenario cpu --repeat 2 --workload deterministic --duration 15 --out outputs/accuracy-cpu

# 不重新跑 eBPF，只聚合已有 check.json 并重生成 CSV/Markdown/SVG
python3 scripts/eval_accuracy.py --from-existing outputs/accuracy/runs --out outputs/accuracy
```

统计口径：

- 正例：`passed=true` 且 `matched_reports` 非空记为 TP，否则记为 FN。
- 负例：`passed=true` 且 `report_count=0` 记为 TN，否则记为 FP。
- `check.json` 缺失或无法解析记为 `infra_error`。
- `extra_report_count` 单独统计，不混入 TP/FN。

产物写入 `outputs/accuracy/`：

```text
outputs/accuracy/
├── accuracy.md
├── accuracy_runs.csv
├── accuracy_summary.csv
├── accuracy_summary.json
├── pass_rate_by_scenario.svg
├── error_breakdown.svg
└── runs/
```

## 测试集配置

测试集在 `tests/scenarios.yaml`：

- `cpu/io/mem/lock/syscall`：正向异常场景
- `idle`：兼容旧配置的 CPU 空载别名
- `idle_cpu/idle_io/idle_lock/idle_syscall`：分场景负向空载场景
- `report_all`：`--scenario all --report` 汇总报告场景

每个场景声明期望的异常类型、关联对象类型、关键指标、证据链字段和宽松数值下限。
`scripts/test_local.sh` 负责运行负载，`cmd/rca-testcheck` 负责读取该配置并断言输出。
正例会在 workload 存活期间采集 ground truth：CPU/lock 按 tid 校验，mem/syscall 按 tgid 校验，
I/O 按测试文件所在块设备校验；未命中 workload 的额外报告会写入 warning，便于定位误报。

## 产物目录

每次运行都会写入：

```text
test-results/<timestamp>/
├── env.txt
├── run.log
├── cpu/
│   ├── output.json
│   ├── ebpf-rca.stderr
│   ├── workload.log
│   ├── ground_truth.json
│   ├── ground_truth.log
│   ├── check.log
│   └── check.json
└── ...
```

`output.json` 是 `ebpf-rca --format json` 的原始输出；`check.json` 是机器可读的校验结果；
`workload.log` 和 `ebpf-rca.stderr` 用于排查负载或 eBPF 挂载失败。

## 常见失败

- `missing readable /sys/kernel/btf/vmlinux`：先运行 `make vmlinux`，或确认内核启用 BTF。
- `attach ... permission denied`：用 root 运行，或授予 `CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN`。
- `sudo cannot run non-interactively`：`sudo -n` 没有可用凭据；先 `sudo -v` 或配置免密 sudo。
- `sudo ... no new privileges`：当前进程被容器/沙箱设置了 no-new-privileges，必须在宿主终端或允许提权的执行环境运行。
- `go: downloading ... connect: connection refused`：Go module cache 未预热；按“准备”中的 `GOMODCACHE/GOPROXY=off` 命令先验证离线缓存，必要时临时 `GO_OFFLINE=0 ./out/run-real-ebpf-e2e.sh` 在线预热一次。
- `stress-ng is required`：在仓库根目录运行 `bash setup_env.sh --no-build`，脚本会源码构建本地版本。
- apt/dpkg 报配置未完成：执行 `sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a`。
- I/O 场景无报告：确认 `--io-path` 位于真实磁盘文件系统，不在 tmpfs；如果磁盘极快，可临时降低正例阈值，例如 `--threshold 0.50`。
- 内存场景无报告：机器可用内存太多时可临时设置 `MEM_BYTES=90% make test-local`。
- 锁场景无报告：默认只保留阻塞栈命中锁/同步符号的报告；可用 `--lock-include-blocking` 临时查看普通长阻塞，用 `--lock-topn` 控制每窗口输出数量。

## 清理

```bash
make test-local-clean
```
