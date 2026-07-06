package collector

import (
	"testing"
	"unsafe"
)

func TestBPFStructLayouts(t *testing.T) {
	tests := []struct {
		name  string
		goSz  uintptr
		bpfSz uintptr
	}{
		{"cpu task_stat", unsafe.Sizeof(taskStat{}), unsafe.Sizeof(cpuTaskStat{})},
		{"block dev_stat", unsafe.Sizeof(ioStat{}), unsafe.Sizeof(blockDevStat{})},
		{"mem mem_stat", unsafe.Sizeof(memStat{}), unsafe.Sizeof(memMemStat{})},
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
