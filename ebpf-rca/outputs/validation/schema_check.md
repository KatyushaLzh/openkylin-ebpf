# ebpf-rca 结构化输出校验报告

每个输入文档均经过严格 JSON、会话生命周期与报告语义校验。

## 汇总

| 场景 | 记录数 | PASS | WARN | FAIL | 平均分 |
|---|---:|---:|---:|---:|---:|
| unknown | 25 | 0 | 0 | 25 | 0.0 |

## 明细

| 文件 | 序号 | 场景 | 状态 | 分数 | 证据条数 | 问题 |
|---|---:|---|---:|---:|---:|---|
| `outputs/repro/raw/io_report_raw.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/repro/raw/lock_report_raw.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/repro/raw/syscall_report_raw.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/repro/raw/mem_report_raw.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/repro/raw/cpu_report_raw.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/repro/lock_report.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/repro/cpu_report.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/repro/mem_report.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/repro/io_report.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/repro/syscall_report.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/bench/tool_output/cpu_r2_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/bench/tool_output/mem_r1_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/syscall_r2_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/bench/tool_output/mem_r2_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/io_r3_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/io_r1_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/syscall_r3_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/bench/tool_output/lock_r3_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/cpu_r3_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/bench/tool_output/cpu_r1_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
| `outputs/bench/tool_output/io_r2_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/lock_r1_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/mem_r3_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/lock_r2_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:document[0][0] missing required fields: root_cause_code |
| `outputs/bench/tool_output/syscall_r1_tool.json` | 0 | unknown | FAIL | 0 | 0 | validation_error:invalid JSONL line 1: Expecting property name enclosed in double quotes: line 1 column 2 (char 1) |
