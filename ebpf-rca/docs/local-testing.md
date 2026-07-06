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
CPU/内存/锁场景需要 `stress-ng`。
如果 openKylin 的 `stress-ng` 包因 `libipsec-mb0` 依赖缺失无法安装，测试脚本会自动使用
`../.build_deps/bin/stress-ng` 中的源码构建版本。

自动化环境建议使用非交互 sudo：

```bash
sudo -n -E bash scripts/test_local.sh preflight --no-build
sudo -n -E bash scripts/test_local.sh all --duration 30 --no-build
```

`sudo -n` 不会弹密码；如果当前 shell 没有 sudo timestamp 或免密配置，它会立即失败。
此时先在 VM 终端执行一次 `sudo -v`，或切换到 root shell 再跑测试。

## 常用命令

```bash
# 只检查环境，不运行负载
bash scripts/test_local.sh preflight

# 快速烟测：CPU + syscall
make test-smoke

# 五类正向异常场景
make test-local

# 空载负向测试，检查基础误报
make test-negative

# 汇总 Markdown 报告测试
make test-report
```

也可以单独运行某个场景：

```bash
bash scripts/test_local.sh cpu --duration 20
bash scripts/test_local.sh scenario --scenario io --duration 30
make test-local TEST_DURATION=60
```

## 测试集配置

测试集在 `tests/scenarios.yaml`：

- `cpu/io/mem/lock/syscall`：正向异常场景
- `idle`：负向空载场景
- `report_all`：`--scenario all --report` 汇总报告场景

每个场景声明期望的异常类型、关联对象类型、关键指标、证据链字段和宽松数值下限。
`scripts/test_local.sh` 负责运行负载，`cmd/rca-testcheck` 负责读取该配置并断言输出。

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
- `stress-ng is required`：在仓库根目录运行 `bash setup_env.sh --no-build`，脚本会源码构建本地版本。
- apt/dpkg 报配置未完成：执行 `sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a`。
- I/O 场景无报告：确认 `--io-path` 位于真实磁盘文件系统，不在 tmpfs。
- 内存场景无报告：机器可用内存太多时可临时设置 `MEM_BYTES=90% make test-local`。
- 锁场景输出 `长时间阻塞等待`：仍视作可接受信号；若要更强锁证据，需要结合阻塞栈符号。

## 清理

```bash
make test-local-clean
```
