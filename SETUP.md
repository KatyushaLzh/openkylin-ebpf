# ebpf-rca 环境搭建技术文档

> 第三届中国研究生操作系统开源创新大赛 · 系统创新赛道
> 目标平台：openKylin Kernel 6.6+, x86_64 / ARM64
> 本文档适配**中国国内网络环境**（gitee 镜像、goproxy.cn 代理）

---

## 目录

1. [编译链路总览](#1-编译链路总览)
2. [环境要求速查表](#2-环境要求速查表)
3. [各组件 OS 级解释](#3-各组件-os-级解释)
4. [快速搭建（自动化脚本）](#4-快速搭建自动化脚本)
5. [手动分步搭建](#5-手动分步搭建)
6. [国内网络适配方案](#6-国内网络适配方案)
7. [验证与运行](#7-验证与运行)
8. [常见问题排查](#8-常见问题排查)

---

## 1. 编译链路总览

项目的完整构建管线涉及 **内核态字节码编译** 和 **用户态 Go 二进制编译** 两条路径的交汇：

```
                       ┌──────────────────────────────────────┐
                       │          /sys/kernel/btf/vmlinux     │
                       │       (内核 BTF 类型信息, CONFIG_)     │
                       └──────────┬───────────────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │   bpftool btf dump ...    │  ① 生成 vmlinux.h
                    │   输出 C 类型定义头文件      │     (全量内核类型)
                    └─────────────┬─────────────┘
                                  │
    ┌─────────────────────────────┼─────────────────────────────┐
    │                             │                             │
    ▼                             ▼                             ▼
┌───────────┐            ┌───────────────────┐         ┌───────────────┐
│ libbpf-dev│            │  bpf/*.bpf.c      │         │  clang -target│
│ 提供 helper │──include──▶  (5个采集探针)     │──编译──▶│  bpf -O2 -g   │
│ /CORE 声明  │            │  #include vmlinux │         │  → *.bpfel.o  │
└───────────┘            └───────────────────┘         └───────┬───────┘
    │                                                          │
    │                                                          ▼
    │                                                  ┌───────────────┐
    │                                                  │  bpf2go 工具  │
    │                                                  │ 将 .o 嵌入 Go │
    │                                                  │ 生成加载器代码  │
    │                                                  └───────┬───────┘
    │                                                          │
    └──────────────────────┬───────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  go build       │  用户态二进制
                  │  → bin/ebpf-rca │  (加载eBPF/采集/检测/RCA)
                  └─────────────────┘
```

关键设计思想：
- **vmlinux.h** 是 CO-RE（Compile Once, Run Everywhere）的基石，等价于「内核所有结构体类型的完整导出」。它让 eBPF 程序不依赖特定内核版本的头文件。
- **bpf2go** 是 cilium/ebpf 提供的代码生成器，等价于 `clang` + `bpftool gen skeleton` 的 Go 版本封装。
- **libbpf 头文件** 提供 BPF helper 函数声明（`bpf_map_lookup_elem` 等）和 CO-RE 辅助宏（`BPF_CORE_READ` 等），不参与运行时链接——仅编译时使用。

---

## 2. 环境要求速查表

| 组件 | 最低版本 | 用途 | 备注 |
|------|---------|------|------|
| **Kernel** | ≥ 6.6 | eBPF 运行时 | 需 `CONFIG_DEBUG_INFO_BTF=y` |
| **BTF** | 任意 | CO-RE 类型重定位 | `/sys/kernel/btf/vmlinux` 必须存在 |
| **clang** | ≥ 12 | 编译 .bpf.c → BPF 字节码 | LLVM 后端提供 BPF target |
| **llvm-strip** | 任意 | 剥离 .o 调试符号减体积 | 随 clang 一起安装 |
| **Go** | ≥ 1.22 | 编译用户态二进制 | go.mod 声明 1.22 |
| **bpftool** | ≥ 7.0 | 从 BTF 生成 vmlinux.h | openKylin **未打包**，需源码编译 |
| **libbpf-dev** | ≥ 1.3 | 提供 BPF helper 头文件 | 包含 `bpf_helpers.h`、`bpf_core_read.h` 等 |
| **fio** | 任意 | I/O 场景负载注入 | 可用 apt 安装 |
| **stress-ng** | 支持 `cpu/vm/mutex` | CPU/内存/锁场景负载注入 | openKylin apt 包可能依赖缺失；脚本会源码构建 |

运行时还会逐项验证 typed BTF 挂载点：`sched_switch/sched_wakeup`、
`block_rq_issue/block_rq_complete`、`sys_enter/sys_exit`、`mark_victim`，以及
`do_futex` 的 `fentry/fexit`。内核即使带 BTF，只要缺少其中任一 BTF 类型/函数，默认
`--allow-partial=false` 也会明确失败，不能把 collector 未加载解释为“未发现异常”。
CPU 启动盲区修复还需要允许 per-CPU `perf_event_open`；lock preflight 要求 root 从
`/proc/kallsyms` 读到非零地址（受 `kernel.kptr_restrict` 影响）。

系统包依赖（编译 bpftool 需要）：
| 包名 | 用途 |
|------|------|
| `libelf-dev` | ELF 文件解析（bpftool 读取 .o 文件） |
| `zlib1g-dev` | 压缩支持 |
| `libcap-dev` | POSIX capabilities |

---

## 3. 各组件 OS 级解释

### 3.1 为什么需要 BTF？

eBPF 程序运行在内核态，需要访问内核数据结构（如 `task_struct`、`rq`）。传统方式需要针对每个内核版本携带匹配的头文件，导致二进制不可移植。

**BTF（BPF Type Format）** 是内核自描述的元数据格式，将每个结构体的大小、成员偏移量、类型信息编码为紧凑的二进制格式。eBPF 加载器在加载 `.o` 文件时，根据运行中内核的 BTF 自动重定位结构体成员偏移——这就是 **CO-RE（Compile Once, Run Everywhere）**。

```
编译时（本机）:                    加载时（目标机）:
  clang 编译 .bpf.c                 libbpf/cilium 加载器
  读取 vmlinux.h 类型定义    →      读取 /sys/kernel/btf/vmlinux
  生成带 CO-RE reloc 的 .o          重定位 → 修正偏移量 → 加载到内核
```

### 3.2 bpftool 的角色

bpftool 是内核 BPF 子系统的标准管理工具，但本项目只用其 **BTF dump** 功能：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

这条命令将内核 BTF 元数据反序列化为标准 C 结构体定义，等价于「用二进制 BTF 反向生成内核全部类型的 C 头文件」。

### 3.3 libbpf 头文件的角色

项目中的 `.bpf.c` 文件包含两行关键 include：

```c
#include "vmlinux.h"          // 内核类型（来自 BTF dump）
#include <bpf/bpf_helpers.h>  // BPF helper 声明 + CO-RE 宏
```

`bpf_helpers.h` 不参与运行时链接——它是**纯声明文件**，告诉 clang「存在这样一个 helper 函数，参数和返回值分别是什么类型」。实际的 helper 调用由内核在验证阶段解析。

### 3.4 bpf2go 的编译流程

`bpf2go` 是 cilium/ebpf 的代码生成工具，封装了以下步骤：

```
.bpf.c  ──[clang -target bpf]──▶  .bpfel.o    (BPF 字节码 ELF)
                                    │
                     ┌──────────────┘
                     ▼
              bpf2go 读取 ELF sections
              提取 maps / programs 定义
                     │
                     ▼
              .bpfel.go (Go 类型定义 + loadXxxObjects() 函数)
```

生成的 `loadXxxObjects()` 内部调用 cilium/ebpf 的 `LoadAndAssign()`，该函数完成 CO-RE 重定位、map 创建、程序验证等一系列内核交互。

---

## 4. 快速搭建（自动化脚本）

```bash
# 先进入你 clone 下来的仓库根目录
bash setup_env.sh
```

脚本功能：
- 若 dpkg 存在半配置包，先提示并尝试 `sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a`
- 自动检测内核版本、BTF、clang、Go 环境
- **libbpf 走 gitee 镜像**，**bpftool 走 GitHub 直连**（gitee 无 bpftool 镜像）
- openKylin 没有可直接安装的 `bpftool` 时，自动源码编译到 `.build_deps/bpftool/src/bpftool`
- openKylin 的 `stress-ng` apt 包因 `libipsec-mb0` 缺失失败时，自动源码编译到 `.build_deps/bin/stress-ng`
- **自动配置 GOPROXY** 为 `goproxy.cn`（GitHub 不通时）
- 所有第三方构建产物放在 **`.build_deps/`** 持久化目录（避免 `/tmp` 被系统清理）
- 生成 vmlinux.h → 编译 eBPF 字节码 → 编译用户态二进制
- **可重复执行**（幂等）

脚本选项：

| 选项 | 作用 |
|------|------|
| `--no-build` | 仅搭建环境依赖，跳过项目编译 |
| `--force-bpftool` | 强制重新编译 bpftool |
| `--force-libbpf` | 强制重新准备 libbpf 头文件 |
| `--force-stress-ng` | 强制重新准备本地 stress-ng |
| `--skip-stress-ng` | 跳过 fio/stress-ng 等测试负载工具准备 |
| `-h` | 显示帮助 |

---

## 5. 手动分步搭建

如果自动化脚本无法使用，按以下步骤手动搭建：
除系统包安装命令外，本节示例默认从仓库根目录执行，因此 `"$PWD/.build_deps"` 指向项目内的本地依赖缓存。

### 5.1 安装系统编译依赖

```bash
# 如果上一轮 apt/debconf 中断过，先修复半配置包
sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a

# 必须（bpftool 编译依赖 + libbpf 头文件）
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y clang llvm libelf-dev zlib1g-dev libcap-dev libbpf-dev

# 可选（复现场景用）
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y fio
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y stress-ng
```

如果 openKylin 源中的 `stress-ng` 因 `libipsec-mb0` 缺失无法安装，不要伪造依赖或强行软链
`libipsec-mb1`；这是 ABI/SONAME 层面的不匹配。直接使用项目本地源码版：

```bash
# 自动准备本地 stress-ng，跳过项目编译
# 在仓库根目录
bash setup_env.sh --no-build

# 调试时可将本地源码版放到 PATH 前面
export PATH="$PWD/.build_deps/bin:$PATH"
stress-ng --version
```

当前项目测试脚本会自动优先查找仓库根目录下的 `.build_deps/bin/stress-ng`，
因此无需把源码版安装到 `/usr/bin`。

手动源码构建等价流程如下：

```bash
BUILD_DIR="$PWD/.build_deps"
mkdir -p "$BUILD_DIR/bin"
curl -fL -o "$BUILD_DIR/stress-ng.tar.gz" \
  https://codeload.github.com/ColinIanKing/stress-ng/tar.gz/refs/tags/V0.21.03
mkdir -p "$BUILD_DIR/stress-ng-extract"
tar -xzf "$BUILD_DIR/stress-ng.tar.gz" -C "$BUILD_DIR/stress-ng-extract"
rm -rf "$BUILD_DIR/stress-ng-src"
mv "$BUILD_DIR"/stress-ng-extract/* "$BUILD_DIR/stress-ng-src"
make -C "$BUILD_DIR/stress-ng-src" -j"$(nproc)"
ln -sf "$BUILD_DIR/stress-ng-src/stress-ng" "$BUILD_DIR/bin/stress-ng"
"$BUILD_DIR/bin/stress-ng" --cpu 1 --timeout 1s --metrics-brief
```

如果无法 `sudo`：
- **libbpf 头文件** 可以从 gitee 克隆替代（见 5.3）
- **libelf-dev/zlib1g-dev/libcap-dev** 是 bpftool 编译必需，需要在有权限的机器上编译 bpftool 后拷贝二进制

### 5.2 获取 bpftool

> **注意**：openKylin 的 `linux-tools-*` 包中不含 bpftool 二进制，仅有一个 `/usr/sbin/bpftool` wrapper 脚本（会打印 WARNING 提示找不到对应内核版本的 bpftool）。必须从源码编译。

**方案 A：GitHub 源码编译（当前环境 GitHub 可达）**

```bash
# 使用项目持久化目录 .build_deps/（避免 /tmp 被系统清理）
BUILD_DIR="$PWD/.build_deps"
mkdir -p "$BUILD_DIR"

# 1. 克隆依赖（libbpf 走 gitee 镜像，bpftool 走 GitHub）
git clone --depth=1 https://gitee.com/mirrors/libbpf.git  "$BUILD_DIR/libbpf"
git clone --depth=1 https://github.com/libbpf/bpftool.git   "$BUILD_DIR/bpftool"

# 2. 将 libbpf 软链到 bpftool 期望的位置
rm -rf "$BUILD_DIR/bpftool/libbpf"
ln -s "$BUILD_DIR/libbpf" "$BUILD_DIR/bpftool/libbpf"

# 3. 编译
make -C "$BUILD_DIR/bpftool/src" -j$(nproc)

# 4. 加入 PATH（永久生效）
echo "export PATH=\"$BUILD_DIR/bpftool/src:\$PATH\"" >> ~/.bashrc
export PATH="$BUILD_DIR/bpftool/src:$PATH"
bpftool version   # 应输出 bpftool v7.x
```

**方案 B：完全走 gitee（GitHub 不通时）**

gitee 上 bpftool 镜像不稳定（可能 405），此时可手动替换 libbpf 后编译：

```bash
BUILD_DIR="$PWD/.build_deps"
mkdir -p "$BUILD_DIR"

# 用 GitHub 直连或代理获取 bpftool 源码，仅 libbpf 走 gitee
git clone --depth=1 https://gitee.com/mirrors/libbpf.git "$BUILD_DIR/libbpf"
# bpftool 源码可从已缓存的副本或 linux-source 包获取（见下方方案 C）
```

**方案 C：从 linux-source 包（离线 / 纯国内环境）**

```bash
sudo -n apt-get install linux-source-6.6.0
LINUX_SRC_DIR="${TMPDIR:-/tmp}/linux-source-6.6.0"
tar xf /usr/src/linux-source-6.6.0.tar.xz -C "${TMPDIR:-/tmp}"
make -C "$LINUX_SRC_DIR/tools/bpf/bpftool" -j"$(nproc)"
```

### 5.3 准备 libbpf 头文件

如果通过 `apt-get install libbpf-dev` 安装了系统包，头文件已在 `/usr/include/bpf/`，**跳过此步**。

否则从 gitee 克隆并创建软链：

```bash
BUILD_DIR="$PWD/.build_deps"
git clone --depth=1 https://gitee.com/mirrors/libbpf.git "$BUILD_DIR/libbpf"

# 在项目内创建 bpf/bpf/ 目录并软链头文件
# 原因：.bpf.c 中 #include <bpf/bpf_helpers.h>，clang 通过 -I../../bpf
# 解析时会查找 bpf/bpf/bpf_helpers.h
mkdir -p ebpf-rca/bpf/bpf
ln -sf "$BUILD_DIR/libbpf/src/bpf_helpers.h"      ebpf-rca/bpf/bpf/bpf_helpers.h
ln -sf "$BUILD_DIR/libbpf/src/bpf_helper_defs.h"  ebpf-rca/bpf/bpf/bpf_helper_defs.h
ln -sf "$BUILD_DIR/libbpf/src/bpf_core_read.h"    ebpf-rca/bpf/bpf/bpf_core_read.h
ln -sf "$BUILD_DIR/libbpf/src/bpf_endian.h"       ebpf-rca/bpf/bpf/bpf_endian.h
ln -sf "$BUILD_DIR/libbpf/src/bpf_tracing.h"      ebpf-rca/bpf/bpf/bpf_tracing.h
ln -sf "$BUILD_DIR/libbpf/src/bpf.h"              ebpf-rca/bpf/bpf/bpf.h
ln -sf "$BUILD_DIR/libbpf/src/btf.h"              ebpf-rca/bpf/bpf/btf.h
ln -sf "$BUILD_DIR/libbpf/src/libbpf_common.h"    ebpf-rca/bpf/bpf/libbpf_common.h
```

### 5.4 配置 Go 模块代理

```bash
# 如果 GitHub 不通（常见于国内服务器），设置国内代理
export GOPROXY=https://goproxy.cn,direct

# 建议永久配置
echo 'export GOPROXY=https://goproxy.cn,direct' >> ~/.bashrc
```

### 5.5 生成 vmlinux.h

```bash
cd ebpf-rca
BPFTOOL=../.build_deps/bpftool/src/bpftool
tmp=bpf/vmlinux.h.tmp
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null > "$tmp"
sed -i '1{/^skipping /d}' "$tmp"
test "$(wc -l < "$tmp")" -gt 50000
mv "$tmp" bpf/vmlinux.h

# 验证
wc -l bpf/vmlinux.h   # 应输出 140000+ 行
head -1 bpf/vmlinux.h # 应输出 #ifndef __VMLINUX_H__
```

**注意**：不要直接执行 `bpftool ... > bpf/vmlinux.h` 做试错。shell 会先打开并截断目标文件，
如果命中的还是 openKylin 的 wrapper 或 bpftool 执行失败，已有的 `vmlinux.h` 会被清空。
`setup_env.sh` 和 `make vmlinux` 都已经改成“写临时文件 → 校验行数 → 原子替换”。

### 5.6 编译项目

```bash
cd ebpf-rca

# 1. 下载 Go 依赖
GOPROXY=https://goproxy.cn,direct go mod tidy

# 2. 编译 eBPF 探针（bpf2go 自动调 clang 编译 .bpf.c）
GOPROXY=https://goproxy.cn,direct go generate ./...

# 验证生成产物
ls internal/collector/{cpu,lock,block,mem,syscall}_bpfel.o
ls internal/collector/{cpu,lock,block,mem,syscall}_bpfel.go

# 3. 编译 Go 用户态二进制
CGO_ENABLED=0 GOPROXY=https://goproxy.cn,direct go build -buildvcs=false -o bin/ebpf-rca ./cmd/ebpf-rca
```

---

## 6. 国内网络适配方案

### 6.1 Git 仓库镜像对照

| GitHub 源 | Gitee 镜像 | 可用性 | 用途 |
|-----------|-----------|--------|------|
| `github.com/libbpf/libbpf` | `gitee.com/mirrors/libbpf` | ✅ 稳定 | bpftool 编译依赖 + libbpf 头文件 |
| `github.com/libbpf/bpftool` | `gitee.com/mirrors/bpftool` | ❌ 不可用 | 生成 vmlinux.h（**仅能走 GitHub**） |

> **openKylin 2.0 SP2 / Kernel 6.6.0-22 实测结论**：`gitee.com/mirrors/bpftool` 返回 405，不存在公开镜像。bpftool 必须从 GitHub 直连或通过 git 代理获取，也可从 `linux-source-6.6.0` 内核源码包中提取。

如果 GitHub 不通，配置 git 代理：

```bash
git config --global http.proxy http://127.0.0.1:7890
git config --global https.proxy http://127.0.0.1:7890
```

### 6.2 Go 模块代理对照

| 代理 | URL | 备注 |
|------|-----|------|
| goproxy.cn | `https://goproxy.cn` | 七牛 CDN，国内首选 |
| aliyun | `https://mirrors.aliyun.com/goproxy/` | 备用 |

### 6.3 openKylin apt 源

当前 openKylin 2.0 nile 已内置 `clang`、`go`、`libelf-dev` 等包，但有两个实测坑：

- **`bpftool` 未独立打包**：`linux-tools-6.6.0-22-generic` 中可能只有 perf/turbostat 等，`/usr/sbin/bpftool` 是 wrapper，不是真正二进制。
- **`stress-ng` 可能不可安装**：仓库里的包依赖 `libipsec-mb0`，但源里只有 `libipsec-mb1`，因此 apt 会报“没有可安装候选”。

本项目的 `setup_env.sh` 对这两个点都采用源码构建兜底。

---

## 7. 验证与运行

### 7.1 环境验证清单

```bash
# 内核 BTF
ls -la /sys/kernel/btf/vmlinux          # 必须存在，通常 3-7MB

# bpftool（注意：需用完整路径，避免 openKylin 的 wrapper 假阳性）
#   /usr/sbin/bpftool 只是一个壳脚本，会打印 WARNING——
#   真正的 bpftool 是我们编译的版本：
./.build_deps/bpftool/src/bpftool version
#   应输出 "bpftool v7.x ... features: llvm, ..." 而非 WARNING

# vmlinux.h
wc -l ebpf-rca/bpf/vmlinux.h            # 应 > 100000 行
head -1 ebpf-rca/bpf/vmlinux.h          # #ifndef __VMLINUX_H__

# bpf2go 生成产物
ls ebpf-rca/internal/collector/*_bpfel.o # 5 个 .o 文件

# Go 二进制
file ebpf-rca/bin/ebpf-rca               # ELF 64-bit executable
ebpf-rca/bin/ebpf-rca --help             # 应打印 CLI 参数

# 测试负载工具
./.build_deps/bin/stress-ng --version
./.build_deps/bin/stress-ng --cpu 1 --timeout 1s --metrics-brief
fio --version
```

### 7.2 运行示例

**需要 root 权限**（加载 eBPF 程序需 `CAP_BPF`/`CAP_PERFMON`）：
如果用于自动化测试，可把下面的 `sudo` 替换为 `sudo -n`；前提是当前用户已有 sudo timestamp
或已配置免密 sudo，否则 `sudo -n` 会直接失败而不会弹密码。

```bash
cd ebpf-rca

# 场景① CPU 异常检测；JSON 在结束时输出单个 DiagnosticSession
sudo ./bin/ebpf-rca --scenario cpu --duration 60s --format json

# 需要实时逐条 AnomalyReport 时使用 JSONL
sudo ./bin/ebpf-rca --scenario cpu --format jsonl

# 场景② I/O 延迟检测
sudo ./bin/ebpf-rca --scenario io --format md

# 场景③ 内存压力检测
sudo ./bin/ebpf-rca --scenario mem --format md

# 场景④ 锁竞争检测
sudo ./bin/ebpf-rca --scenario lock --format md

# 场景⑤ 系统调用热点检测
sudo ./bin/ebpf-rca --scenario syscall --format md

# 全部 5 个场景同时运行，60 秒后生成汇总报告
sudo ./bin/ebpf-rca --scenario all --duration 60s --report report.md

# 自定义阈值和判定窗口
sudo ./bin/ebpf-rca --scenario cpu --threshold 0.85 --sustain 5 --interval 2s
```

### 7.3 复现异常场景（用于测试）

```bash
# 终端1：启动检测
sudo ./bin/ebpf-rca --scenario cpu --format json

# 终端2：制造 CPU 压力（使用系统 stress-ng 或 .build_deps/bin/stress-ng）
bash scripts/repro_cpu.sh 60
```

更多复现脚本见 `scripts/` 目录。

---

## 8. 常见问题排查

### Q1: `go generate` 报 `fatal error: 'bpf/bpf_helpers.h' file not found`

**原因**：libbpf 头文件不在 clang 的搜索路径中。

**解决**：
- **方案 A**：`sudo -n apt-get install libbpf-dev`（头文件安装到 `/usr/include/bpf/`）
- **方案 B**：执行 5.3 节的 gitee 软链方案

### Q2: `bpftool btf dump` 输出第一行是 "skipping /sys/kernel/btf/vmlinux..."

**原因**：bpftool 的诊断信息写到了 stdout。

**解决**：
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null > bpf/vmlinux.h
# 如果仍有问题：
sed -i '1{/^skipping /d}' bpf/vmlinux.h
```

### Q3: 运行时 `Error: failed to create map: operation not permitted`

**原因**：没有 root 权限或 `kernel_lockdown` 限制了 BPF。

**检查**：
```bash
cat /sys/kernel/security/lockdown  # 应为 none 或 integrity
```

**解决**：使用 `sudo` 运行，或在内核启动参数中添加 `lockdown=integrity`。

### Q4: `go: github.com/cilium/ebpf@v0.16.0: Get "https://proxy.golang.org/...": dial tcp: i/o timeout`

**原因**：`proxy.golang.org` 在国内不可达。

**解决**：
```bash
export GOPROXY=https://goproxy.cn,direct
```

### Q5: bpftool `make` 报 `libbpf/src/hashmap.h: No such file or directory`

**原因**：bpftool 的 libbpf 子模块未初始化。

**解决**：
```bash
# 方案 A：从 gitee 克隆 libbpf 并软链
BUILD_DIR="$PWD/.build_deps"
git clone --depth=1 https://gitee.com/mirrors/libbpf.git "$BUILD_DIR/libbpf"
rm -rf "$BUILD_DIR/bpftool/libbpf"
ln -s "$BUILD_DIR/libbpf" "$BUILD_DIR/bpftool/libbpf"

# 方案 B：初始化子模块（需 GitHub 连通）
git submodule update --init --recursive
```

### Q6: 内核版本是 6.6 但 BTF 文件不存在

**原因**：内核未启用 `CONFIG_DEBUG_INFO_BTF=y`。

**检查**：
```bash
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF
# 或
zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF
```

**解决**：需要重新编译内核并启用该选项，或更换支持 BTF 的内核。

### Q7: `bpftool version` 输出 WARNING "bpftool not found for kernel X.X.X-XX"

**原因**：你执行的是 openKylin 自带的 `/usr/sbin/bpftool` wrapper 脚本，它会尝试调用 `/usr/lib/linux-tools/$(uname -r)/bpftool`，但 openKylin 的内核 tools 包中**没有打包 bpftool 二进制**（只有 perf/turbostat 等）。

**解决**：
```bash
# 用我们编译的 bpftool 完整路径
./.build_deps/bpftool/src/bpftool version

# 或确保 PATH 中我们编译的版本优先于系统 wrapper
export PATH="$PWD/.build_deps/bpftool/src:$PATH"
which bpftool   # 应输出 .build_deps/.../bpftool，而非 /usr/sbin/bpftool
```

### Q8: 之前编译好的 bpftool / libbpf 找不到了

**原因**：`/tmp` 和 `/var/tmp` 下的文件会被系统定期清理（tmpwatch/systemd-tmpfiles）。

**解决**：使用项目内的持久化目录 `.build_deps/`：
```bash
# setup_env.sh 自动使用此目录，手动编译时也指定它
BUILD_DIR="$PWD/.build_deps"
```

已丢失的话，重新执行 `bash setup_env.sh --force-bpftool` 即可恢复。

### Q9: `apt-get install stress-ng` 报 `libipsec-mb0` 没有候选

**原因**：openKylin 源里的 `stress-ng` 包依赖 `libipsec-mb0`，但当前源只提供
`libipsec-mb1`。这不是普通包名变化，而是共享库 SONAME/ABI 级别的依赖不匹配。

**解决**：
```bash
# 在仓库根目录
bash setup_env.sh --no-build
./.build_deps/bin/stress-ng --version
```

不要通过手工改依赖、软链 `libipsec-mb.so.0` 到 `libipsec-mb.so.1` 等方式绕过；
那会把 ABI 风险带进测试结果。

### Q10: `dpkg -l` 里出现 `iF iperf3` 或 apt 提示配置未完成

**原因**：某些包安装过程触发 debconf 交互问题，非交互环境下可能停在“已解包但配置失败”。
这种状态会污染后续 apt 安装。

**解决**：
```bash
sudo -n env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
# 如果 apt 仍提示依赖未修复：
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -f install
```

如果 `sudo -n` 输出“需要密码”，说明当前 shell 没有 sudo timestamp 或免密配置；先在 VM 终端执行
一次普通 `sudo -v`，或切到 root shell 后再运行环境脚本。

---

## 附：目录结构速查

```
OS2026/
├── setup_env.sh                    # ★ 一键环境搭建脚本
├── SETUP.md                        # ★ 本文档
├── ebpf-rca/
│   ├── README.md                   # 项目使用说明
│   ├── Makefile                    # 构建编排（make deps/vmlinux/build/bench）
│   ├── go.mod / go.sum             # Go 模块依赖
│   ├── bpf/
│   │   ├── vmlinux.h               # 从 BTF 生成的内核类型导出（>14万行）
│   │   ├── bpf/                    # libbpf 头文件软链目录（无 libbpf-dev 时）
│   │   ├── cpu.bpf.c               # 场景① CPU 异常探针
│   │   ├── block.bpf.c             # 场景② I/O 延迟探针
│   │   ├── mem.bpf.c               # 场景③ 内存压力探针
│   │   ├── lock.bpf.c              # 场景④ 锁竞争探针
│   │   └── syscall.bpf.c           # 场景⑤ 系统调用热点探针
│   ├── cmd/ebpf-rca/main.go        # CLI 入口
│   ├── internal/
│   │   ├── collector/              # eBPF 加载/挂载/差分读取
│   │   ├── detector/               # 阈值+连续窗口异常判定
│   │   ├── rca/                    # 确定性根因分析引擎
│   │   ├── schema/                 # 统一结构化输出（7字段+证据链）
│   │   ├── output/                 # JSON/YAML/Markdown 渲染
│   │   ├── report/                 # 多场景汇总报告
│   │   ├── ksym/                   # 内核符号解析
│   │   └── syscalls/               # syscall 号→名映射
│   ├── scripts/                    # 部署/复现/benchmark 脚本
│   └── docs/                       # 设计/测试/容器/排错文档
└── .build_deps/                    # setup_env.sh 构建的第三方依赖
    ├── bin/                        # 本地工具软链（stress-ng）
    ├── bpftool/                    # bpftool 源码+编译产物
    ├── libbpf/                     # libbpf 源码（gitee 克隆）
    └── stress-ng-src/              # stress-ng 源码+编译产物
```
