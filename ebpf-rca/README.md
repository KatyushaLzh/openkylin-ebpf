# ebpf-rca

基于 eBPF 的系统异常观测与根因定位工具，面向 openKylin Kernel 6.6+。工具以内核态聚合、用户态窗口差分和确定性 RCA 规则输出可回溯诊断结果，覆盖 CPU、I/O、内存、锁/阻塞、系统调用热点五类场景。

## 快速开始

```bash
cd /data/usershare/OS2026
bash setup_env.sh --no-build

cd ebpf-rca
make vmlinux
make build

sudo ./bin/ebpf-rca --scenario cpu --format json
sudo ./bin/ebpf-rca --scenario all --duration 60s --report report.md
```

常用复现脚本：

```bash
bash scripts/repro_cpu.sh 60
bash scripts/repro_io.sh 60
bash scripts/repro_mem.sh 60
bash scripts/repro_lock.sh 60
bash scripts/repro_syscall.sh 30
```

## CLI 参数

| 参数 | 默认 | 说明 |
|---|---:|---|
| `--scenario` | `cpu` | `cpu|io|mem|lock|syscall|all` |
| `--interval` | `1s` | 采样窗口 |
| `--threshold` | `0` | 单场景兼容参数；按当前场景解释，`all` 模式禁用 |
| `--cpu-threshold` | `0.90` | CPU 单核占用阈值 |
| `--io-p99-threshold-ms` | `20` | I/O P99 时延阈值 |
| `--mem-avail-floor-pct` | `15` | 可用内存占比下限 |
| `--lock-offcpu-threshold` | `0.30` | off-CPU 阻塞占比阈值 |
| `--syscall-rate-threshold` | `10000` | syscall 调用频率阈值(次/秒) |
| `--target-pid` | `0` | syscall 场景进程过滤；0 表示全局 |
| `--sustain` | `3` | 连续多少个窗口触发 |
| `--duration` | `0` | 总运行时长；0 表示直到 Ctrl-C |
| `--format` | `json` | `json|yaml|md` |
| `--output` | stdout | 流式输出文件 |
| `--report` | 空 | 汇总 Markdown 报告路径 |

`--scenario all` 下请使用各场景专用阈值。一个 `--threshold` 同时套到 CPU 比例、I/O 毫秒、内存百分比和 syscall 频率没有清晰语义，工具会直接报错。

## 输出字段

结构化结果统一使用 `schema.AnomalyReport`，至少包含：

- `anomaly_type`
- `related_object`
- `key_metrics`
- `time_window`
- `suspected_root_cause`
- `confidence`
- `evidence_chain`
- `suggestion`

示例：

```json
{
  "anomaly_type": "CPU异常占用",
  "related_object": { "pid": 1234, "tid": 1234, "comm": "matrixprod" },
  "key_metrics": { "cpu_util": 0.97, "ctx_switch_per_min": 120, "runq_wait_us": 8.3 },
  "time_window": { "start": "2026-07-06T10:00:01Z", "end": "2026-07-06T10:00:04Z" },
  "suspected_root_cause": "用户态计算热点导致 CPU 饱和（计算密集或异常 busy loop）",
  "confidence": 0.93,
  "evidence_chain": [
    { "type": "metric", "name": "cpu_util", "value": 0.97, "threshold": 0.9 }
  ],
  "suggestion": "定位用户态热点函数，优化算法或并行度；排查是否存在异常 busy loop"
}
```

## 测试与文档

```bash
go test ./...
make docs-check
make test-smoke
make test-local
make test-negative
make test-report
```

设计细节见 `docs/design.md`；复现和验收见 `docs/testing.md`、`docs/local-testing.md`；openKylin/eBPF 常见问题见 `docs/troubleshooting.md`；容器运行见 `docs/docker.md`。

## 已知限制

- CPU/锁场景当前以 tid 为主，进程级、cgroup、container 聚合是后续增强。
- I/O tracepoint 不暴露 request 指针时，请求 key 使用 `dev+sector+nr_sector+rwbs`，高并发同扇区请求仍可能冲突。
- `raw_syscalls` 是最高开销场景，生产建议配合 `--target-pid`。
- `/proc/kallsyms` 不可读时，锁/阻塞栈只能输出未符号化状态，不能强判锁竞争。
- syscall 名表是常见子集；未知项会显示为 `syscall_<nr>`，报告保留 `syscall_nr`。

## License

eBPF 程序以 GPL 协议加载。用户态代码见仓库根目录 `../LICENSE`。
