# ebpf-rca

基于 eBPF 的系统异常观测与根因定位工具，面向 openKylin Kernel 6.6+。工具以内核态聚合、用户态窗口差分和确定性 RCA 规则输出可回溯诊断结果，覆盖 CPU、I/O、内存、锁/阻塞、系统调用热点五类场景。

## 快速开始

```bash
cd /data/usershare/OS2026
bash setup_env.sh --no-build

cd ebpf-rca
make vmlinux
make generate       # 维护探针时重生成；普通 clean clone 直接使用仓库内跟踪的 bpf2go 产物
make build

sudo ./bin/ebpf-rca --scenario all --format json --duration 60s > session.json
sudo ./bin/ebpf-rca --scenario all --format jsonl       # 实时逐行 AnomalyReport
sudo ./bin/ebpf-rca --scenario all --duration 60s --report report.md
```

手工演示脚本：

```bash
bash scripts/repro_cpu.sh 60
bash scripts/repro_io.sh 60
bash scripts/repro_mem.sh 60
bash scripts/repro_lock.sh 60
bash scripts/repro_syscall.sh 30
```

这些脚本用于现场演示“启动工具 -> 注入负载 -> 输出诊断”的单场景链路。正式准确率验收统一以
deterministic、`--scenario all`、产品默认阈值且不传 `--target-pid` 运行；CPU/mem/lock/syscall
使用可输出独立 oracle 的 `rca-testload`，I/O 仍用 fio。stress 与定向进程树诊断只作附加测试，
不混入主准确率。

评分验收产物：

```bash
sudo -n bash scripts/env_check.sh
make repro-all
make accuracy-full
make bench-full
make validate-output
```

产物写入 `outputs/{env,repro,accuracy,bench,validation}/`。旧版产物是在宽松阈值、单 collector 或 target 模式下得到的历史调试数据，不能作为当前版本准确率/低开销结论。提交数据必须由严格 oracle 流程重新生成：异常类型、`root_cause_code` 和独立 workload 对象需同时匹配，任何额外错误报告计为 FP。

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
| `--lock-include-blocking` | `false` | lock 场景保留未命中锁符号的普通长阻塞 |
| `--lock-topn` | `5` | lock 场景每个窗口最多输出的阻塞线程数 |
| `--syscall-rate-threshold` | `10000` | syscall 调用频率阈值(次/秒) |
| `--target-pid` | `0` | mem/lock/syscall 场景进程树过滤；0 表示全局 |
| `--sustain` | `3` | 连续多少个窗口触发 |
| `--duration` | `0` | 总运行时长；0 表示直到 Ctrl-C |
| `--format` | `json` | `json`=结束时单个 `DiagnosticSession`；`jsonl`=实时逐行报告；另支持 `yaml|md` |
| `--allow-partial` | `false` | 仅 all 模式可用；默认任一 collector 初始化/Poll 失败即非零退出 |
| `--output` | stdout | 流式输出文件 |
| `--report` | 空 | 汇总 Markdown 报告路径 |

`--scenario all` 下请使用各场景专用阈值。一个 `--threshold` 同时套到 CPU 比例、I/O 毫秒、内存百分比和 syscall 频率没有清晰语义，工具会直接报错。

## 输出字段

`--format json` 的顶层是单个 `DiagnosticSession`，包含环境、判定配置、五个 collector 生命周期/健康状态以及 `reports[]`。`reports[]` 中每项统一使用 `schema.AnomalyReport`，至少包含：

- `anomaly_type`
- `root_cause_code`
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
  "schema_version": "1.0",
  "started_at": "2026-07-06T10:00:00Z",
  "ended_at": "2026-07-06T10:01:00Z",
  "elapsed_ms": 60000,
  "environment": { "hostname": "openkylin", "os": "linux", "architecture": "amd64", "kernel_release": "6.6.0", "btf": true },
  "configuration": {
    "scenario": "all", "interval_ms": 1000, "sustain": 3, "allow_partial": false,
    "thresholds": { "cpu_util": 0.9, "io_p99_ms": 20, "mem_available_floor_pct": 15, "lock_offcpu_ratio": 0.3, "syscall_calls_per_sec": 10000 }
  },
	"collectors": [
	  { "name": "cpu", "requested": true, "initialized": true, "state": "stopped", "poll_count": 60, "health": { "program_runtime_ns": 0, "program_run_count": 0, "map_memory_bytes": 0, "counters": {} } },
	  { "name": "io", "requested": true, "initialized": true, "state": "stopped", "poll_count": 60, "health": { "program_runtime_ns": 0, "program_run_count": 0, "map_memory_bytes": 0, "counters": {} } },
	  { "name": "mem", "requested": true, "initialized": true, "state": "stopped", "poll_count": 60, "health": { "program_runtime_ns": 0, "program_run_count": 0, "map_memory_bytes": 0, "counters": {} } },
	  { "name": "lock", "requested": true, "initialized": true, "state": "stopped", "poll_count": 60, "health": { "program_runtime_ns": 0, "program_run_count": 0, "map_memory_bytes": 0, "counters": {} } },
	  { "name": "syscall", "requested": true, "initialized": true, "state": "stopped", "poll_count": 60, "health": { "program_runtime_ns": 0, "program_run_count": 0, "map_memory_bytes": 0, "counters": {} } }
  ],
  "partial": false,
  "reports": [{
    "anomaly_type": "CPU异常占用",
    "root_cause_code": "cpu.compute_hotspot",
    "related_object": { "pid": 1234, "tid": 1236, "comm": "matrixprod", "scope": "process" },
    "key_metrics": { "top_thread_cpu_cores": 0.97, "process_cpu_cores": 1.91 },
    "time_window": { "start": "2026-07-06T10:00:01Z", "end": "2026-07-06T10:00:04Z", "elapsed_ms": 3000 },
    "suspected_root_cause": "用户态计算热点导致 CPU 饱和",
    "confidence": 0.93,
    "evidence_chain": [{ "type": "metric", "name": "process_cpu_cores", "value": 1.91, "threshold": 0.9 }],
    "suggestion": "定位用户态热点函数并检查并行度"
  }]
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
make accuracy-full
make bench-full
make validate-output
```

实机 eBPF 全链路复跑可使用本地 wrapper：

```bash
./out/run-real-ebpf-e2e.sh
```

该脚本默认离线使用当前用户的 Go module cache，构建阶段不应出现 `go: downloading`；
root 权限只用于内部 `scripts/test_local.sh ... --no-build` 阶段，不要用 `sudo` 直接运行整个 wrapper。

设计细节见 `docs/design.md`；复现和验收见 `docs/testing.md`、`docs/local-testing.md`；openKylin/eBPF 常见问题见 `docs/troubleshooting.md`；容器运行见 `docs/docker.md`。

## 已知限制

- Kernel 6.6+BTF、typed tracepoint、`do_futex` fentry/fexit、per-CPU `perf_event_open` 和可解析的 `/proc/kallsyms` 是硬前提；不提供会产生错误指标的旧 tracepoint 降级路径。
- 本轮没有实现 cgroup/container 聚合和运行时插件系统；`--target-pid` 只表达进程树范围。
- `/proc/kallsyms` 不可读或地址被 `kptr_restrict` 清零时，lock collector 在 preflight 明确失败；不能把无法分类的内核同步等待认证为健康零报告。
- 已提供 x86_64/ARM64 验收工作流与证据打包脚本；仓库中的跨平台结论以两台 openKylin 实机重新生成的 SHA256 manifest 为准。

## License

eBPF 程序以 GPL 协议加载。用户态代码见仓库根目录 `../LICENSE`。
