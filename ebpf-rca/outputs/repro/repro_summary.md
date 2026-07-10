# ebpf-rca 五类异常复现报告

- 生成时间：2026-07-09T12:02:02Z
- workload duration：60s
- tool duration：68s

| 场景 | 状态 | 工具输出 | 负载日志 | 说明 |
|---|---|---|---|---|
| cpu | PASS | `outputs/repro/cpu_report.json` | `outputs/repro/raw/cpu_workload.log` | tool output generated; raw=outputs/repro/raw/cpu_report_raw.json |
| io | PASS | `outputs/repro/io_report.json` | `outputs/repro/raw/io_workload.log` | tool output generated; raw=outputs/repro/raw/io_report_raw.json |
| mem | PASS | `outputs/repro/mem_report.json` | `outputs/repro/raw/mem_workload.log` | tool output generated; raw=outputs/repro/raw/mem_report_raw.json; target_pid=82472 |
| lock | PASS | `outputs/repro/lock_report.json` | `outputs/repro/raw/lock_workload.log` | tool output generated; raw=outputs/repro/raw/lock_report_raw.json; target_pid=82663 |
| syscall | PASS | `outputs/repro/syscall_report.json` | `outputs/repro/raw/syscall_workload.log` | tool output generated; raw=outputs/repro/raw/syscall_report_raw.json; target_pid=82904 |

## 使用说明

1. 将 `*_report.json` 作为技术报告第 4.1 节的实际输出样例。
2. 将 `raw/*_workload.log` 作为异常注入证据。
3. 运行 `python3 scripts/validate_report.py outputs/repro/*.json` 检查结构化字段和证据链。
