package collector

// 由 cpu.bpf.c 生成 CO-RE 字节码与 Go 加载器（cpu_bpfel.go / cpu_bpfel.o）。
// 运行 `go generate ./...` 或 `make generate`（需 clang/llvm 与 bpf/vmlinux.h）。
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I../../bpf" cpu ../../bpf/cpu.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I../../bpf" lock ../../bpf/lock.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I../../bpf" block ../../bpf/block.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I../../bpf" mem ../../bpf/mem.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I../../bpf" syscall ../../bpf/syscall.bpf.c
