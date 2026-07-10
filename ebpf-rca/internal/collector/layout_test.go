package collector

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestBPFStructLayouts(t *testing.T) {
	tests := []struct {
		name  string
		goSz  uintptr
		bpfSz uintptr
	}{
		{"cpu task_stat", unsafe.Sizeof(taskStat{}), unsafe.Sizeof(cpuTaskStat{})},
		{"cpu task_key", unsafe.Sizeof(taskKey{}), unsafe.Sizeof(cpuTaskKey{})},
		{"cpu oncpu_info", unsafe.Sizeof(oncpuInfo{}), unsafe.Sizeof(cpuOncpuInfo{})},
		{"cpu stack_key", unsafe.Sizeof(cpuStackKeyLocal{}), unsafe.Sizeof(cpuStackKey{})},
		{"cpu stack_stat", unsafe.Sizeof(cpuStackStatLocal{}), unsafe.Sizeof(cpuStackStat{})},
		{"block dev_stat", unsafe.Sizeof(ioStat{}), unsafe.Sizeof(blockDevStat{})},
		{"block health_stat", unsafe.Sizeof(ioHealthStat{}), unsafe.Sizeof(blockHealthStat{})},
		{"mem mem_stat", unsafe.Sizeof(memStat{}), unsafe.Sizeof(memMemStat{})},
		{"mem oom_stat", unsafe.Sizeof(oomStat{}), unsafe.Sizeof(memOomStat{})},
		{"lock lock_key", unsafe.Sizeof(lockKey{}), unsafe.Sizeof(lockLockKey{})},
		{"lock lock_stat", unsafe.Sizeof(lockStat{}), unsafe.Sizeof(lockLockStat{})},
		{"syscall sc_key", unsafe.Sizeof(scKey{}), unsafe.Sizeof(syscallScKey{})},
		{"syscall sc_stat", unsafe.Sizeof(scStat{}), unsafe.Sizeof(syscallScStat{})},
	}
	for _, tt := range tests {
		if tt.goSz != tt.bpfSz {
			t.Fatalf("%s size mismatch: Go=%d BPF=%d", tt.name, tt.goSz, tt.bpfSz)
		}
	}
}

func TestGeneratedBPFIntegritySpecs(t *testing.T) {
	cpu, err := loadCpu()
	if err != nil {
		t.Fatal(err)
	}
	if prog := cpu.Programs["handle_seed_oncpu"]; prog == nil || prog.Type != ebpf.PerfEvent {
		t.Fatalf("CPU running-task heartbeat is missing or has wrong type: %#v", prog)
	}

	block, err := loadBlock()
	if err != nil {
		t.Fatal(err)
	}
	if m := block.Maps["startup_boundary_ns"]; m == nil || m.Type != ebpf.Array || m.MaxEntries != 1 || m.ValueSize != 8 {
		t.Fatalf("I/O startup boundary map mismatch: %#v", m)
	}
	if m := block.Maps["start"]; m == nil || m.Type != ebpf.Hash ||
		m.ValueSize != uint32(unsafe.Sizeof(blockRequestState{})) || m.ValueSize != 40 {
		t.Fatalf("I/O request lifecycle state layout mismatch: %#v", m)
	}

	loaders := []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{"mem", loadMem},
		{"lock", loadLock},
		{"syscall", loadSyscall},
	}
	for _, loader := range loaders {
		spec, err := loader.load()
		if err != nil {
			t.Fatalf("load %s spec: %v", loader.name, err)
		}
		for _, mapName := range []string{"target_tgids", "observed_tgids"} {
			m := spec.Maps[mapName]
			if m == nil || m.Type != ebpf.Hash || m.ValueSize != 8 {
				t.Fatalf("%s %s must store uint64 process identity: %#v", loader.name, mapName, m)
			}
		}
	}
	lockSpec, err := loadLock()
	if err != nil {
		t.Fatal(err)
	}
	for _, mapName := range []string{"futex_active", "offcpu_start", "lock_stats"} {
		if m := lockSpec.Maps[mapName]; m == nil || m.Type != ebpf.Hash {
			t.Fatalf("lock %s must be non-evicting HASH: %#v", mapName, m)
		}
	}
	if m := lockSpec.Maps["offcpu_start"]; m == nil ||
		m.ValueSize != uint32(unsafe.Sizeof(lockOffcpuInfo{})) || m.ValueSize != 48 {
		t.Fatalf("lock offcpu_start identity layout mismatch: %#v", m)
	}
	if m := lockSpec.Maps["lock_stat_zero"]; m == nil || m.Type != ebpf.PerCPUArray ||
		m.MaxEntries != 1 || m.ValueSize != uint32(unsafe.Sizeof(lockStat{})) {
		t.Fatalf("lock map-backed zero template mismatch: %#v", m)
	}
}

func TestAllModeLogicalMapPayloadFitsBudget(t *testing.T) {
	loaders := []func() (*ebpf.CollectionSpec, error){loadCpu, loadBlock, loadMem, loadLock, loadSyscall}
	var bytes uint64
	for _, load := range loaders {
		spec, err := load()
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range spec.Maps {
			bytes += uint64(m.KeySize+m.ValueSize) * uint64(m.MaxEntries)
		}
	}
	const budget = uint64(64 << 20)
	if bytes >= budget {
		t.Fatalf("logical all-mode map payload %d bytes leaves no room under 64 MiB", bytes)
	}
	t.Logf("logical all-mode map payload: %d bytes (kernel memlock is verified on-host)", bytes)
}
