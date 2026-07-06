#!/usr/bin/env bash
# ===========================================================================
# ebpf-rca 环境搭建脚本（中国国内环境适配版）
#
# 功能：
#   1. 检测系统环境（内核/架构/BTF/clang/go/make）
#   2. 安装缺失系统依赖（优先 apt，无 sudo 则提示，全部 sudo -n 非交互）
#   3. 构建 bpftool（openKylin 未打包，从 GitHub 源码编译；gitee 无此镜像）
#   4. 准备 libbpf 头文件（优先系统包，否则走 gitee 克隆）
#   5. 准备测试负载工具（fio；stress-ng apt 失败则源码构建）
#   6. 生成 vmlinux.h（CO-RE 核心，从内核 BTF 导出）
#   7. 编译 eBPF 字节码 + Go 用户态二进制
#
# 适配：
#   - libbpf → gitee.com 镜像；bpftool → GitHub（gitee 无 bpftool 镜像）
#   - go modules → goproxy.cn 代理
#
# 用法：
#   bash setup_env.sh [--no-build] [--force-bpftool] [--force-libbpf] [--force-stress-ng] [--skip-stress-ng]
#
# 选项：
#   --no-build       仅搭建环境依赖，不编译项目
#   --force-bpftool  强制重新编译 bpftool（即使已存在）
#   --force-libbpf   强制重新准备 libbpf 头文件（即使已存在）
#   --force-stress-ng 强制重新准备本地 stress-ng
#   --skip-stress-ng  跳过 stress-ng/fio 等测试负载工具准备
#   -h, --help       显示帮助
# ===========================================================================

set -euo pipefail

# ------------------------------ 常量定义 ------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/ebpf-rca"
BUILD_DIR="${SCRIPT_DIR}/.build_deps"          # 第三方构建产物隔离目录
BPFTOOL_DIR="${BUILD_DIR}/bpftool"
LIBBPF_DIR="${BUILD_DIR}/libbpf"
STRESS_NG_VERSION="${STRESS_NG_VERSION:-0.21.03}"
STRESS_NG_DIR="${BUILD_DIR}/stress-ng-src"
STRESS_NG_TARBALL="${BUILD_DIR}/stress-ng.tar.gz"
STRESS_NG_BIN_DIR="${BUILD_DIR}/bin"
STRESS_NG_BIN="${STRESS_NG_BIN_DIR}/stress-ng"
HEADERS_LINK_DIR="${PROJECT_DIR}/bpf/bpf"      # 项目内 bpf/bpf/ 头文件软链目录

# 国内镜像源
GITEE_LIBBPF="https://gitee.com/mirrors/libbpf.git"
GITHUB_BPFTOOL="https://github.com/libbpf/bpftool.git"
GITHUB_STRESS_NG_TAG="https://codeload.github.com/ColinIanKing/stress-ng/tar.gz/refs/tags/V${STRESS_NG_VERSION}"
GITHUB_STRESS_NG_MASTER="https://codeload.github.com/ColinIanKing/stress-ng/tar.gz/refs/heads/master"
# 注意：gitee.com/mirrors/bpftool 不存在（405），bpftool 仅能从 GitHub 获取

# 颜色输出
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "${BLUE}[STEP]${NC} $*"; }

# ------------------------------ 参数解析 ------------------------------
NO_BUILD=false
FORCE_BPFTOOL=false
FORCE_LIBBPF=false
FORCE_STRESS_NG=false
SKIP_STRESS_NG=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)       NO_BUILD=true;      shift ;;
        --force-bpftool)  FORCE_BPFTOOL=true;  shift ;;
        --force-libbpf)   FORCE_LIBBPF=true;   shift ;;
        --force-stress-ng) FORCE_STRESS_NG=true; shift ;;
        --skip-stress-ng) SKIP_STRESS_NG=true; shift ;;
        -h|--help)
            sed -n '3,28p' "$0"
            exit 0
            ;;
        *) error "未知参数: $1"; exit 1 ;;
    esac
done

# ------------------------------ 工具函数 ------------------------------
have_cmd() { command -v "$1" &>/dev/null; }
ver_ge()   { printf '%s\n%s\n' "$2" "$1" | sort -V -C 2>/dev/null; }
can_sudo() { sudo -n true &>/dev/null; }
sudo_env() { sudo -n env DEBIAN_FRONTEND=noninteractive "$@"; }
sudo_apt_get() { sudo_env apt-get "$@"; }

repair_dpkg_if_needed() {
    local audit
    if ! audit="$(dpkg --audit 2>&1)"; then
        if can_sudo; then
            audit="$(sudo_env dpkg --audit 2>&1 || true)"
        else
            warn "无法以当前用户检查 dpkg 状态；若 apt 失败，请手动执行: sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a"
            return 0
        fi
    fi
    if [[ -z "$audit" ]]; then
        return 0
    fi

    warn "dpkg 存在未完成配置的包，可能导致 apt 安装失败"
    echo "$audit" | sed 's/^/  /'
    if can_sudo; then
        warn "尝试非交互修复: sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a"
        sudo_env dpkg --configure -a || warn "dpkg 自动修复失败，请手动执行上面的命令"
    else
        warn "无免密 sudo 权限，请手动执行: sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a"
    fi
}

fetch_url() {
    local url="$1" dst="$2"
    if have_cmd curl; then
        curl -fL --retry 2 --connect-timeout 15 -o "$dst" "$url"
    elif have_cmd wget; then
        wget -O "$dst" "$url"
    else
        return 1
    fi
}

check_bin() {
    local name="$1" min_ver="${2:-}"
    if have_cmd "$name"; then
        local out ver
        out=$("$name" --version 2>&1 || "$name" version 2>&1 || true)
        ver=$(grep -oP '[0-9]+(\.[0-9]+)+' <<<"$out" | head -1 || true)
        if [[ -n "$min_ver" && -n "$ver" ]] && ! ver_ge "$ver" "$min_ver"; then
            warn "$name 版本 $ver < $min_ver，可能不兼容"
            return 1
        fi
        info "$name: ${ver:-OK}"
        return 0
    else
        warn "未找到 $name"
        return 1
    fi
}

# ---------------------------- Step 0: 基础环境检查 --------------------
step "Step 0: 基础环境检查"

echo "  系统: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "  内核: $(uname -r)"
echo "  架构: $(uname -m)"

# 内核版本 >= 6.6
KERNEL_VER=$(uname -r | cut -d- -f1)
if ! ver_ge "$KERNEL_VER" "6.6"; then
    error "需要内核 >= 6.6，当前: $KERNEL_VER"
    exit 1
fi
info "内核版本 $KERNEL_VER >= 6.6 ✓"

# BTF 存在性
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    error "/sys/kernel/btf/vmlinux 不存在——内核缺少 BTF 支持（需 CONFIG_DEBUG_INFO_BTF=y）"
    exit 1
fi
VMLINUX_SIZE=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo 0)
info "BTF 可用 ($(( VMLINUX_SIZE / 1024 / 1024 ))MB) ✓"

# 编译器与工具链
check_bin clang  "12.0" || {
    warn "尝试安装 clang/llvm..."
    can_sudo && sudo_apt_get install -y clang llvm || warn "无免密 sudo 权限，请手动安装 clang/llvm"
    check_bin clang "12.0" || { error "clang 安装失败"; exit 1; }
}
check_bin llvm-strip
check_bin go     "1.22"
check_bin make

# ---------------------------- Step 1: 系统包依赖 -----------------------
step "Step 1: 系统包依赖检查与安装"

repair_dpkg_if_needed

MISSING_PKGS=""
for pkg in libelf-dev zlib1g-dev libcap-dev; do
    dpkg -s "$pkg" &>/dev/null || MISSING_PKGS="$MISSING_PKGS $pkg"
done
# libbpf-dev 单独检查（可能通过 gitee 源绕过）
dpkg -s libbpf-dev &>/dev/null && HAVE_LIBBPF_DEV=true || HAVE_LIBBPF_DEV=false

if [[ -n "$MISSING_PKGS" ]]; then
    warn "缺少包: $MISSING_PKGS"
    if can_sudo; then
        sudo_apt_get update -qq && sudo_apt_get install -y $MISSING_PKGS
        info "系统包安装完成 ✓"
    else
        warn "无免密 sudo 权限，请手动执行: sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y $MISSING_PKGS"
    fi
else
    info "系统编译依赖已就绪 ✓"
fi

if $HAVE_LIBBPF_DEV; then
    info "libbpf-dev 已由系统包管理器安装 ✓"
else
    warn "libbpf-dev 未安装（将使用 gitee 源替代）"
fi

# ---------------------------- Step 2: bpftool --------------------------
step "Step 2: bpftool 准备"

bpftool_ready() {
    local out
    have_cmd bpftool || return 1
    out="$(bpftool version 2>&1 || true)"
    [[ "$out" == bpftool\ v* ]] && ! grep -q "WARNING: bpftool not found" <<<"$out"
}

if bpftool_ready && ! $FORCE_BPFTOOL; then
    BPFTOOL_BIN="$(which bpftool)"
    info "bpftool 可用: $BPFTOOL_BIN ($(bpftool version 2>&1 | head -1)) ✓"
else
    if $FORCE_BPFTOOL; then
        warn "强制重建 bpftool"
    else
        warn "bpftool 不可用（openKylin 未打包），从源码编译..."
    fi

    mkdir -p "$BUILD_DIR"

    # 如果已有 bpftool 目录但 libbpf 子模块缺失，做清理
    if [[ -d "$BPFTOOL_DIR" ]] && $FORCE_BPFTOOL; then
        rm -rf "$BPFTOOL_DIR"
    fi

    if [[ ! -d "$BPFTOOL_DIR" ]]; then
        info "克隆 bpftool（GitHub）..."
        if ! git clone --depth=1 "$GITHUB_BPFTOOL" "$BPFTOOL_DIR" 2>&1; then
            # GitHub 不通的兜底提示
            error "bpftool GitHub 克隆失败——请检查网络或配置 git 代理"
            error "备选方案：sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install linux-source-6.6.0 然后从 tools/bpf/bpftool/ 编译"
            exit 1
        fi
    fi

    # 准备 libbpf 子模块（bpftool 编译依赖 libbpf 源码）
    if [[ -d "$BPFTOOL_DIR" ]]; then
        # 准备 libbpf 源码（bpftool 需要其内部头文件）
        if [[ ! -d "$LIBBPF_DIR" ]]; then
            info "从 gitee 克隆 libbpf（bpftool 编译依赖）..."
            git clone --depth=1 "$GITEE_LIBBPF" "$LIBBPF_DIR" 2>&1 || {
                error "libbpf gitee 克隆失败——请检查网络"
                exit 1
            }
        fi

        # bpftool Makefile 期望 libbpf 源码在 ../libbpf/src
        # 如果 bpftool 自带 libbpf 子模块且已初始化，优先使用；否则软链我们的克隆
        if [[ -d "$BPFTOOL_DIR/libbpf/src" ]]; then
            info "bpftool 子模块 libbpf 已就绪"
        else
            rm -rf "$BPFTOOL_DIR/libbpf"
            ln -sf "$LIBBPF_DIR" "$BPFTOOL_DIR/libbpf"
            info "libbpf 软链到 bpftool 目录完成"
        fi

        info "编译 bpftool..."
        make -C "$BPFTOOL_DIR/src" -j"$(nproc)" 2>&1 | tail -3

        if [[ -x "$BPFTOOL_DIR/src/bpftool" ]]; then
            BPFTOOL_BIN="$BPFTOOL_DIR/src/bpftool"
            # 尝试安装到系统（可选，无 sudo 则跳过）。后续仍使用本地完整路径，
            # 避免 openKylin 的 /usr/sbin/bpftool wrapper 被 PATH 命中。
            if can_sudo; then
                sudo -n make -C "$BPFTOOL_DIR/src" install 2>/dev/null || true
            fi
            info "bpftool 编译成功: $BPFTOOL_BIN ($($BPFTOOL_BIN version 2>&1 | head -1)) ✓"
        else
            error "bpftool 编译失败"
            exit 1
        fi
    else
        # 兜底：bpftool 目录不存在（前面的 clone 已失败退出，此分支不应到达）
        error "bpftool 源码目录不存在"
        error "请手动获取 bpftool: 安装 linux-source-6.6.0 并从 tools/bpf/bpftool/ 编译"
        exit 1
    fi
fi

# -------------------------- Step 3: libbpf 头文件 ----------------------
step "Step 3: libbpf 头文件准备"

libbpf_headers_ready() {
    # 检查 bpf/bpf_helpers.h 在系统路径或项目 bpf/bpf/ 目录下是否可解析
    local test_file="${PROJECT_DIR}/bpf/.libbpf_header_check.c"
    cat > "$test_file" <<'EOF'
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
#include <bpf/bpf_helpers.h>
EOF
    if clang -fsyntax-only -I"${PROJECT_DIR}/bpf" "$test_file" &>/dev/null; then
        rm -f "$test_file"
        return 0
    fi
    rm -f "$test_file"
    return 1
}

if libbpf_headers_ready && ! $FORCE_LIBBPF; then
    info "libbpf 头文件可解析 ✓"
else
    if $FORCE_LIBBPF; then
        warn "强制重新准备 libbpf 头文件"
    else
        warn "libbpf 头文件无法解析（未安装 libbpf-dev），从 gitee 源准备..."
    fi

    # 确保 libbpf 源码已克隆
    if [[ ! -d "$LIBBPF_DIR/src" ]]; then
        info "从 gitee 克隆 libbpf..."
        git clone --depth=1 "$GITEE_LIBBPF" "$LIBBPF_DIR" 2>&1 || {
            error "libbpf gitee 克隆失败"
            exit 1
        }
    fi

    # 在项目 bpf/bpf/ 目录下创建头文件软链
    # 原因：.bpf.c 使用 #include <bpf/bpf_helpers.h>，clang 通过 -I../../bpf 解析，
    # 会查找 bpf/bpf/bpf_helpers.h
    mkdir -p "$HEADERS_LINK_DIR"

    _required_headers=(
        bpf_helpers.h
        bpf_helper_defs.h
        bpf_core_read.h
        bpf_endian.h
        bpf_tracing.h
        bpf.h
        btf.h
        libbpf_common.h
    )

    _all_linked=true
    for h in "${_required_headers[@]}"; do
        _src="${LIBBPF_DIR}/src/${h}"
        _dst="${HEADERS_LINK_DIR}/${h}"
        if [[ -f "$_src" ]]; then
            ln -sf "$_src" "$_dst"
        else
            warn "libbpf 源码中未找到 $h"
            _all_linked=false
        fi
    done

    if $_all_linked && libbpf_headers_ready; then
        info "libbpf 头文件软链到 ${HEADERS_LINK_DIR}/ 完成 ✓"
    else
        error "libbpf 头文件准备失败"
        if ! $HAVE_LIBBPF_DEV; then
            error "建议执行: sudo -n apt-get install libbpf-dev"
        fi
        exit 1
    fi
fi

# -------------------------- Step 4: Go 代理配置 ------------------------
step "Step 4: Go 模块代理配置"

# 检测 GitHub 连通性
if curl -sI --connect-timeout 3 https://github.com &>/dev/null; then
    info "GitHub 直连可用 ✓"
else
    warn "GitHub 直连不可达，配置 GOPROXY 为 goproxy.cn"
    export GOPROXY="https://goproxy.cn,direct"
    info "GOPROXY=https://goproxy.cn,direct ✓"
fi

# -------------------------- Step 5: 测试负载工具 -----------------------
step "Step 5: 测试负载工具准备（fio / stress-ng）"

stress_ng_suitable() {
    local bin="$1"
    [[ -x "$bin" ]] || return 1
    "$bin" --version &>/dev/null || return 1
    "$bin" --help 2>/dev/null | grep -Eq -- '--cpu|cpu N' || return 1
    "$bin" --help 2>/dev/null | grep -Eq -- '--vm|vm N' || return 1
    "$bin" --help 2>/dev/null | grep -Eq -- '--mutex|--futex|mutex N|futex N'
}

build_local_stress_ng() {
    mkdir -p "$BUILD_DIR" "$STRESS_NG_BIN_DIR"

    if [[ -x "$STRESS_NG_BIN" && "$FORCE_STRESS_NG" == false ]] && stress_ng_suitable "$STRESS_NG_BIN"; then
        info "本地 stress-ng 已可用: $STRESS_NG_BIN ($($STRESS_NG_BIN --version 2>&1 | head -1)) ✓"
        return 0
    fi

    if ! have_cmd cc && ! have_cmd gcc; then
        warn "未找到 C 编译器，无法源码构建 stress-ng"
        return 1
    fi

    if [[ ! -f "$STRESS_NG_TARBALL" || "$FORCE_STRESS_NG" == true ]]; then
        info "下载 stress-ng ${STRESS_NG_VERSION} 源码包..."
        if ! fetch_url "$GITHUB_STRESS_NG_TAG" "$STRESS_NG_TARBALL"; then
            warn "固定版本下载失败，尝试 GitHub master 源码包..."
            fetch_url "$GITHUB_STRESS_NG_MASTER" "$STRESS_NG_TARBALL" || return 1
        fi
    fi

    if [[ ! -d "$STRESS_NG_DIR" || "$FORCE_STRESS_NG" == true ]]; then
        local extract_dir extracted
        extract_dir="${BUILD_DIR}/stress-ng-extract"
        rm -rf "$extract_dir"
        mkdir -p "$extract_dir"
        tar -xzf "$STRESS_NG_TARBALL" -C "$extract_dir"
        extracted="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -1)"
        [[ -n "$extracted" ]] || return 1
        rm -rf "$STRESS_NG_DIR"
        mv "$extracted" "$STRESS_NG_DIR"
        rm -rf "$extract_dir"
    fi

    info "编译本地 stress-ng..."
    make -C "$STRESS_NG_DIR" -j"$(nproc)" 2>&1 | tail -5
    [[ -x "$STRESS_NG_DIR/stress-ng" ]] || return 1
    ln -sf "$STRESS_NG_DIR/stress-ng" "$STRESS_NG_BIN"
    stress_ng_suitable "$STRESS_NG_BIN" || return 1
    info "本地 stress-ng 准备完成: $STRESS_NG_BIN ($($STRESS_NG_BIN --version 2>&1 | head -1)) ✓"
}

if $SKIP_STRESS_NG; then
    warn "--skip-stress-ng 模式，跳过 fio/stress-ng 测试负载工具准备"
else
    if have_cmd fio; then
        info "fio 可用: $(command -v fio) ($(fio --version 2>/dev/null | head -1)) ✓"
    elif can_sudo; then
        warn "未找到 fio，尝试 apt 安装..."
        sudo_apt_get install -y fio || warn "fio 安装失败；I/O E2E 场景需要手动安装 fio"
    else
        warn "未找到 fio；无免密 sudo 权限，请手动安装: sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y fio"
    fi

    if [[ -x "$STRESS_NG_BIN" && "$FORCE_STRESS_NG" == false ]] && stress_ng_suitable "$STRESS_NG_BIN"; then
        info "stress-ng 本地版本可用: $STRESS_NG_BIN ($($STRESS_NG_BIN --version 2>&1 | head -1)) ✓"
    elif have_cmd stress-ng && [[ "$FORCE_STRESS_NG" == false ]] && stress_ng_suitable "$(command -v stress-ng)"; then
        info "stress-ng 系统版本可用: $(command -v stress-ng) ($(stress-ng --version 2>&1 | head -1)) ✓"
    else
        warn "stress-ng 不可用或缺少 cpu/vm/mutex/futex stressor"
        if can_sudo; then
            warn "尝试 apt 安装 stress-ng；openKylin 可能因 libipsec-mb0 缺失失败"
            sudo_apt_get install -y stress-ng || warn "apt 安装 stress-ng 失败，将改用源码构建"
        else
            warn "无免密 sudo 权限，跳过 apt 安装 stress-ng"
        fi

        if have_cmd stress-ng && [[ "$FORCE_STRESS_NG" == false ]] && stress_ng_suitable "$(command -v stress-ng)"; then
            info "stress-ng 系统版本可用: $(command -v stress-ng) ($(stress-ng --version 2>&1 | head -1)) ✓"
        else
            build_local_stress_ng || warn "stress-ng 源码构建失败；CPU/内存/锁 E2E 场景将不可用"
        fi
    fi
fi

# ------------------------- Step 6: vmlinux.h 生成 ----------------------
step "Step 6: vmlinux.h 生成（CO-RE 核心类型导出）"

VMLINUX_H="${PROJECT_DIR}/bpf/vmlinux.h"

if [[ -f "$VMLINUX_H" ]] && ! $FORCE_BPFTOOL; then
    _vmlinux_lines=$(wc -l < "$VMLINUX_H")
    if [[ "$_vmlinux_lines" -gt 100000 ]]; then
        info "vmlinux.h 已存在且有效（$_vmlinux_lines 行）✓"
    else
        warn "vmlinux.h 过小（$_vmlinux_lines 行），重新生成..."
        FORCE_REGEN_VMLINUX=true
    fi
else
    FORCE_REGEN_VMLINUX=true
fi

if ${FORCE_REGEN_VMLINUX:-false}; then
    info "从 /sys/kernel/btf/vmlinux 导出类型定义..."
    _vmlinux_tmp="${VMLINUX_H}.tmp"
    if ! "$BPFTOOL_BIN" btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null > "$_vmlinux_tmp"; then
        rm -f "$_vmlinux_tmp"
        error "vmlinux.h 生成失败；保留原文件不覆盖"
        exit 1
    fi

    # bpftool 有时把诊断信息也写进 stdout，清理第一行
    if head -1 "$_vmlinux_tmp" | grep -q '^skipping '; then
        sed -i '1d' "$_vmlinux_tmp"
    fi

    _vmlinux_lines=$(wc -l < "$_vmlinux_tmp")
    if [[ "$_vmlinux_lines" -lt 50000 ]]; then
        rm -f "$_vmlinux_tmp"
        error "vmlinux.h 生成异常（仅 $_vmlinux_lines 行）"
        exit 1
    fi
    mv "$_vmlinux_tmp" "$VMLINUX_H"
    info "vmlinux.h 生成完成（$_vmlinux_lines 行）✓"
fi

# -------------------------- Step 7: 项目编译 ---------------------------
if $NO_BUILD; then
    info "--no-build 模式，跳过项目编译"
else
    step "Step 7: eBPF 字节码 + Go 二进制编译"

    cd "$PROJECT_DIR"

    # 6a. Go 依赖下载
    info "下载 Go 模块依赖..."
    GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" go mod tidy 2>&1 | tail -3
    info "Go 依赖下载完成 ✓"

    # 6b. 编译 .bpf.c → eBPF 字节码 → Go 加载器 (bpf2go)
    info "编译 eBPF 探针（bpf2go + clang）..."
    GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" go generate ./... 2>&1
    _gen_ok=true
    for probe in cpu lock block mem syscall; do
        if [[ ! -f "internal/collector/${probe}_bpfel.o" ]]; then
            error "eBPF 字节码 ${probe}_bpfel.o 缺失"
            _gen_ok=false
        fi
    done
    if $_gen_ok; then
        info "5 个 eBPF 探针全部编译成功 ✓"
    else
        error "部分 eBPF 探针编译失败"
        exit 1
    fi

    # 6c. 编译 Go 用户态二进制
    info "编译 Go 用户态二进制..."
    mkdir -p bin
    CGO_ENABLED=0 GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}" \
        go build -buildvcs=false -o bin/ebpf-rca ./cmd/ebpf-rca 2>&1

    if [[ -x bin/ebpf-rca ]]; then
        _bin_size=$(du -h bin/ebpf-rca | cut -f1)
        info "编译成功: bin/ebpf-rca ($_bin_size) ✓"
    else
        error "Go 二进制编译失败"
        exit 1
    fi
fi

# -------------------------- 完成总结 ----------------------------------
echo ""
echo "════════════════════════════════════════════════════════════"
echo -e "  ${GREEN}✓ ebpf-rca 环境搭建完成${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  关键路径:"
echo "    bpftool:           ${BPFTOOL_BIN:-未安装}"
echo "    vmlinux.h:         ${VMLINUX_H}"
echo "    libbpf 头文件:     ${HEADERS_LINK_DIR}"
echo "    stress-ng:         $([[ -x "$STRESS_NG_BIN" ]] && echo "$STRESS_NG_BIN" || command -v stress-ng 2>/dev/null || echo "未安装")"
echo ""
if [[ -x "${PROJECT_DIR}/bin/ebpf-rca" ]]; then
    echo "  运行方式（需 root 权限加载 eBPF）:"
    echo "    sudo ${PROJECT_DIR}/bin/ebpf-rca --scenario cpu --format json"
    echo "    sudo ${PROJECT_DIR}/bin/ebpf-rca --scenario all --duration 60s --report report.md"
fi
echo ""
echo "  环境变量（建议追加到 ~/.bashrc）:"
echo "    export GOPROXY=https://goproxy.cn,direct"
echo "    export PATH=\"${BUILD_DIR}/bpftool/src:\$PATH\"  # 可选，使 bpftool 全局可用"
echo "    export PATH=\"${STRESS_NG_BIN_DIR}:\$PATH\"      # 可选，使本地 stress-ng 全局可用"
echo ""
