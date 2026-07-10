#!/usr/bin/env bash
# env_check.sh — ebpf-rca 评测环境检查脚本
# 目标：一次性生成可放进技术报告的环境证据，避免评委复现时踩坑。

set -u

OUT_DIR="${OUT_DIR:-outputs/env}"
mkdir -p "$OUT_DIR"
MD="$OUT_DIR/env_report.md"
JSON="$OUT_DIR/env_report.json"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

pass=0
warn=0
fail=0

status_json_items=()

_escape_json() {
  python3 - <<'PY' "$1"
import json, sys
print(json.dumps(sys.argv[1], ensure_ascii=False)[1:-1])
PY
}

record() {
  local level="$1" item="$2" detail="$3"
  case "$level" in
    PASS) pass=$((pass+1));;
    WARN) warn=$((warn+1));;
    FAIL) fail=$((fail+1));;
  esac
  printf '| %s | %s | %s |\n' "$level" "$item" "$detail" >> "$MD"
  local item_e detail_e
  item_e="$(_escape_json "$item")"
  detail_e="$(_escape_json "$detail")"
  status_json_items+=("{\"level\":\"$level\",\"item\":\"$item_e\",\"detail\":\"$detail_e\"}")
}

cmd_ver() {
  local cmd="$1" arg="${2:---version}"
  if command -v "$cmd" >/dev/null 2>&1; then
    local v
    v="$($cmd $arg 2>&1 | head -n 1 | tr -d '\r')"
    record PASS "$cmd" "$v"
  else
    record FAIL "$cmd" "not found"
  fi
}

cmd_ver_optional() {
  local cmd="$1" arg="${2:---version}" note="${3:-optional}"
  if command -v "$cmd" >/dev/null 2>&1; then
    local v
    v="$($cmd $arg 2>&1 | head -n 1 | tr -d '\r')"
    record PASS "$cmd" "$v"
  else
    record WARN "$cmd" "not found；$note"
  fi
}

stress_ng_ver() {
  local bin="${STRESS_NG:-}"
  if [[ -n "$bin" && -x "$bin" ]]; then
    :
  elif [[ -x "../.build_deps/bin/stress-ng" ]]; then
    bin="../.build_deps/bin/stress-ng"
  elif command -v stress-ng >/dev/null 2>&1; then
    bin="$(command -v stress-ng)"
  else
    record FAIL "stress-ng" "not found；性能 benchmark 与附加 stress 回归需要 stress-ng，可运行 make deps 或安装系统包"
    return
  fi
  local v
  v="$("$bin" --version 2>&1 | head -n 1 | tr -d '\r')"
  record PASS "stress-ng" "$v ($bin)"
}

capability_summary() {
  python3 - <<'PY'
from pathlib import Path

bits = {
    "CAP_SYS_ADMIN": 21,
    "CAP_SYS_RESOURCE": 24,
    "CAP_PERFMON": 38,
    "CAP_BPF": 39,
}
cap_eff = 0
for line in Path("/proc/self/status").read_text().splitlines():
    if line.startswith("CapEff:"):
        cap_eff = int(line.split()[1], 16)
        break

have = [name for name, bit in bits.items() if cap_eff & (1 << bit)]
missing_core = [name for name in ("CAP_BPF", "CAP_PERFMON", "CAP_SYS_RESOURCE") if name not in have]
ok = "CAP_SYS_ADMIN" in have or not missing_core
detail = f"CapEff=0x{cap_eff:x}, have={','.join(have) if have else 'none'}"
if ok:
    print(detail)
    raise SystemExit(0)
print(detail + f", missing={','.join(missing_core)}")
raise SystemExit(1)
PY
}

kernel_major_minor_ok() {
  local rel major minor
  rel="$(uname -r)"
  major="${rel%%.*}"
  minor="${rel#*.}"; minor="${minor%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] || return 1
  [[ "$minor" =~ ^[0-9]+$ ]] || return 1
  if (( major > 6 || (major == 6 && minor >= 6) )); then
    return 0
  fi
  return 1
}

{
  echo '# ebpf-rca 评测环境检查报告'
  echo
  echo "- 生成时间：$TS"
  echo "- 主机名：$(hostname 2>/dev/null || echo unknown)"
  echo "- 当前用户：$(id -un 2>/dev/null || echo unknown)"
  echo
  echo '## 结论表'
  echo
  echo '| 状态 | 检查项 | 详情 |'
  echo '|---|---|---|'
} > "$MD"

# OS / kernel / arch
if [[ -r /etc/os-release ]]; then
  os_pretty="$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
  record PASS "操作系统" "$os_pretty"
else
  record WARN "操作系统" "/etc/os-release not readable"
fi

kernel="$(uname -r)"
if kernel_major_minor_ok; then
  record PASS "Kernel >= 6.6" "$kernel"
else
  record WARN "Kernel >= 6.6" "$kernel；赛题目标建议 Kernel 6.6+，低版本需说明兼容性"
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|aarch64|arm64|riscv64) record PASS "CPU 架构" "$arch";;
  *) record WARN "CPU 架构" "$arch；建议至少覆盖 x86_64 / ARM64，能跑 RISC-V 更加分";;
esac

# BTF / eBPF prerequisites
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  size="$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo unknown)"
  record PASS "BTF: /sys/kernel/btf/vmlinux" "exists, size=${size} bytes"
else
  record FAIL "BTF: /sys/kernel/btf/vmlinux" "missing；CO-RE 运行前提不足"
fi

if awk '$1 != "0000000000000000" && $1 != "00000000" { found=1; exit } END { exit !found }' /proc/kallsyms 2>/dev/null; then
  record PASS "kallsyms" "/proc/kallsyms exposes non-zero addresses for lock classification"
else
  record FAIL "kallsyms" "unreadable/zero addresses；lock collector preflight will fail (check root and kernel.kptr_restrict)"
fi
if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
  record PASS "perf_event_paranoid" "$(cat /proc/sys/kernel/perf_event_paranoid)；CPU heartbeat still requires successful per-CPU perf_event_open"
fi

if [[ -d /sys/fs/bpf ]]; then
  if mount | grep -q 'on /sys/fs/bpf type bpf'; then
    record PASS "bpffs" "/sys/fs/bpf mounted"
  else
    record WARN "bpffs" "/sys/fs/bpf exists but not mounted as bpf；必要时 sudo mount -t bpf bpf /sys/fs/bpf"
  fi
else
  record WARN "bpffs" "/sys/fs/bpf not found"
fi

if [[ "$(id -u)" -eq 0 ]]; then
  record PASS "权限" "running as root"
else
  record WARN "权限" "not root；运行 ebpf-rca 需要 root 或 CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN"
  if grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status 2>/dev/null; then
    record FAIL "no_new_privs" "NoNewPrivs=1；sudo/setuid 无法在当前执行环境提权"
  fi
  if cap_detail="$(capability_summary 2>/dev/null)"; then
    record PASS "eBPF capabilities" "$cap_detail"
  else
    record FAIL "eBPF capabilities" "$cap_detail；当前进程无法直接加载 eBPF 程序"
  fi
fi

if [[ -r /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
  record PASS "unprivileged_bpf_disabled" "$(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
fi

# Toolchain
cmd_ver clang --version
cmd_ver llc --version
cmd_ver llvm-strip --version
cmd_ver bpftool version
cmd_ver go version
cmd_ver make --version
cmd_ver gcc --version
cmd_ver git --version
cmd_ver python3 --version

# Workload / benchmark tools
stress_ng_ver
cmd_ver fio --version
cmd_ver_optional pidstat -V "bench 脚本当前使用 ps 采样；安装 sysstat 后可作为补充观测"
cmd_ver perf --version
cmd_ver jq --version

# Project structure
[[ -x ./bin/ebpf-rca ]] && record PASS "bin/ebpf-rca" "executable exists" || record WARN "bin/ebpf-rca" "not found；请先 make build"
for s in cpu io mem lock syscall; do
  if [[ -f "scripts/repro_${s}.sh" ]]; then
    record PASS "scripts/repro_${s}.sh" "exists"
  else
    record FAIL "scripts/repro_${s}.sh" "missing；复现脚本评分项会受影响"
  fi
done

{
  echo
  echo '## 评分相关说明'
  echo
  echo '- 该报告可作为技术报告「运行环境」和「多平台适配」证据。'
  echo '- 若出现 FAIL，建议先修复；若出现 WARN，需要在技术报告「已知限制/适配说明」解释。'
  echo '- 建议在 openKylin Kernel 6.6+ 的 x86_64 与 ARM64 至少各跑一份，并把两份报告截图放入材料。'
  echo
  echo "## 汇总"
  echo
  echo "- PASS：$pass"
  echo "- WARN：$warn"
  echo "- FAIL：$fail"
} >> "$MD"

{
  echo '{'
  echo "  \"generated_at\": \"$TS\","
  echo "  \"host\": \"$(_escape_json "$(hostname 2>/dev/null || echo unknown)")\","
  echo "  \"kernel\": \"$(_escape_json "$kernel")\","
  echo "  \"arch\": \"$(_escape_json "$arch")\","
  echo "  \"summary\": {\"pass\": $pass, \"warn\": $warn, \"fail\": $fail},"
  echo '  "items": ['
  local_i=0
  for item in "${status_json_items[@]}"; do
    if (( local_i > 0 )); then echo ','; fi
    printf '    %s' "$item"
    local_i=$((local_i+1))
  done
  echo
  echo '  ]'
  echo '}'
} > "$JSON"

echo "[env_check] wrote $MD and $JSON"
if (( fail > 0 )); then
  exit 2
fi
exit 0
