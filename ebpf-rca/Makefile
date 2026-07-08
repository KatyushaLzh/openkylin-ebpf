APP      := ebpf-rca
BPF_SRC  := bpf/cpu.bpf.c
VMLINUX  := bpf/vmlinux.h
BPFTOOL  := $(firstword $(wildcard ../.build_deps/bpftool/src/bpftool) bpftool)
TEST_DURATION ?=
TEST_SMOKE_DURATION ?= $(if $(TEST_DURATION),$(TEST_DURATION),15)
TEST_LOCAL_DURATION ?= $(if $(TEST_DURATION),$(TEST_DURATION),30)
TEST_NEGATIVE_DURATION ?= $(if $(TEST_DURATION),$(TEST_DURATION),15)
TEST_REPORT_DURATION ?= $(if $(TEST_DURATION),$(TEST_DURATION),30)
SCORE_DURATION ?= 60
SCORE_REPEAT ?= 3
SCORE_FORMAT ?= json
ACCURACY_REPEAT ?= $(SCORE_REPEAT)
ACCURACY_DURATION ?=
ACCURACY_WORKLOAD ?= stress

.PHONY: all build generate vmlinux deps bench docs-check test-checker test-load test-smoke test-local test-negative test-report test-local-clean env-check repro-all bench-full accuracy-full validate-output report-artifacts clean

all: build

## 生成 vmlinux.h（CO-RE 前提，需 bpftool 与内核 BTF）
vmlinux:
	@tmp="$(VMLINUX).tmp"; \
	if ! "$(BPFTOOL)" btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null > "$$tmp"; then \
		rm -f "$$tmp"; \
		echo "failed to generate $(VMLINUX): check bpftool and /sys/kernel/btf/vmlinux" >&2; \
		exit 1; \
	fi; \
	sed -i '1{/^skipping /d}' "$$tmp"; \
	lines=$$(wc -l < "$$tmp"); \
	if [ "$$lines" -lt 50000 ]; then \
		rm -f "$$tmp"; \
		echo "generated $(VMLINUX) is too small ($$lines lines)" >&2; \
		exit 1; \
	fi; \
	mv "$$tmp" "$(VMLINUX)"; \
	echo "generated $(VMLINUX) ($$lines lines)"

## 由 .bpf.c 生成 CO-RE 字节码与 Go 加载器（需 clang/llvm）
generate:
	go generate ./...

## 编译用户态二进制
build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build -buildvcs=false -o bin/$(APP) ./cmd/$(APP)

## 安装构建依赖（openKylin / Debian 系；走仓库根目录的兼容脚本）
deps:
	cd .. && bash setup_env.sh --no-build

## 性能开销基准（全部场景），结果写入 bench.md
bench: build
	bash scripts/benchmark.sh all bench.md

## 检查技术文档是否与 CLI / 路径保持同步
docs-check:
	bash scripts/check_docs.sh

## 编译本地 E2E 测试输出校验器
test-checker:
	mkdir -p bin
	go build -buildvcs=false -o bin/rca-testcheck ./cmd/rca-testcheck

## 编译本地 E2E 确定性测试负载
test-load:
	mkdir -p bin
	go build -buildvcs=false -o bin/rca-testload ./cmd/rca-testload

## 短烟测：CPU + syscall 两类，适合快速确认链路
test-smoke: build test-checker test-load
	bash scripts/test_local.sh smoke --duration $(TEST_SMOKE_DURATION) --no-build

## 本地 E2E：五类正向异常场景
test-local: build test-checker test-load
	bash scripts/test_local.sh all --duration $(TEST_LOCAL_DURATION) --no-build

## 空载负向测试：检查基础误报
test-negative: build test-checker test-load
	bash scripts/test_local.sh negative --duration $(TEST_NEGATIVE_DURATION) --no-build

## 汇总报告测试：--scenario all + --report
test-report: build test-checker test-load
	bash scripts/test_local.sh report --duration $(TEST_REPORT_DURATION) --no-build

## 评测环境检查，结果写入 outputs/env/
env-check:
	bash scripts/env_check.sh

## 五类异常复现留档，结果写入 outputs/repro/
repro-all: build
	bash scripts/run_all_repro.sh --duration $(SCORE_DURATION) --format $(SCORE_FORMAT)

## baseline vs with_tool 开销基准，结果写入 outputs/bench/
bench-full: build
	bash scripts/bench_overhead.sh --scenario all --duration $(SCORE_DURATION) --repeat $(SCORE_REPEAT) --out outputs/bench

## 多轮诊断准确率评测，结果写入 outputs/accuracy/
accuracy-full: build test-checker test-load
	python3 scripts/eval_accuracy.py --scenario all --repeat $(ACCURACY_REPEAT) --workload $(ACCURACY_WORKLOAD) --out outputs/accuracy --no-build $(if $(ACCURACY_DURATION),--duration $(ACCURACY_DURATION),)

## 校验已生成的 JSON 结构化报告
validate-output:
	@files=$$(find outputs/repro outputs/bench/tool_output -type f -name '*.json' 2>/dev/null); \
	if [ -z "$$files" ]; then \
		echo "no JSON artifacts found under outputs/repro or outputs/bench/tool_output"; \
		exit 0; \
	fi; \
	python3 scripts/validate_report.py $$files || true

## 一键生成技术报告可引用的评测产物
report-artifacts: env-check repro-all bench-full validate-output
	@echo "Artifacts generated under outputs/{env,repro,bench,validation}."
	@echo "Use outputs/bench/bench.md and outputs/validation/schema_check.md in the technical report."

## 清理本地测试产物
test-local-clean:
	rm -rf test-results

clean:
	rm -f bin/$(APP) bin/rca-testcheck bin/rca-testload internal/collector/*_bpfel.go \
	      internal/collector/*_bpfeb.go internal/collector/*.o
