# ebpf-rca 评测环境检查报告

- 生成时间：2026-07-08T07:09:14Z
- 主机名：Katyusha-pc
- 当前用户：root

## 结论表

| 状态 | 检查项 | 详情 |
|---|---|---|
| PASS | 操作系统 | openKylin 2.0 SP2 |
| PASS | Kernel >= 6.6 | 6.6.0-22-generic |
| PASS | CPU 架构 | x86_64 |
| PASS | BTF: /sys/kernel/btf/vmlinux | exists, size=6249772 bytes |
| PASS | bpffs | /sys/fs/bpf mounted |
| PASS | 权限 | running as root |
| PASS | unprivileged_bpf_disabled | 2 |
| PASS | clang | openKylin clang version 17.0.6 (9ok8) |
| PASS | llc | openKylin LLVM version 17.0.6 |
| PASS | llvm-strip | llvm-strip, compatible with GNU strip |
| PASS | bpftool | WARNING: bpftool not found for kernel 6.6.0-22 |
| PASS | go | go version go1.22.1 linux/amd64 |
| PASS | make | GNU Make 4.3 |
| PASS | gcc | gcc (Openkylin 12.3.0-1ok3) 12.3.0 |
| PASS | git | git version 2.43.0 |
| PASS | python3 | Python 3.12.2 |
| PASS | stress-ng | stress-ng, version 0.21.03 (gcc 12.3.0, x86_64 Linux 6.6.0-22-generic) (../.build_deps/bin/stress-ng) |
| PASS | fio | fio-3.36 |
| WARN | pidstat | not found；bench 脚本当前使用 ps 采样；安装 sysstat 后可作为补充观测 |
| PASS | perf | perf version 6.6.127 |
| PASS | jq | jq-1.7 |
| PASS | bin/ebpf-rca | executable exists |
| PASS | scripts/repro_cpu.sh | exists |
| PASS | scripts/repro_io.sh | exists |
| PASS | scripts/repro_mem.sh | exists |
| PASS | scripts/repro_lock.sh | exists |
| PASS | scripts/repro_syscall.sh | exists |

## 评分相关说明

- 该报告可作为技术报告「运行环境」和「多平台适配」证据。
- 若出现 FAIL，建议先修复；若出现 WARN，需要在技术报告「已知限制/适配说明」解释。
- 建议在 openKylin Kernel 6.6+ 的 x86_64 与 ARM64 至少各跑一份，并把两份报告截图放入材料。

## 汇总

- PASS：26
- WARN：1
- FAIL：0
