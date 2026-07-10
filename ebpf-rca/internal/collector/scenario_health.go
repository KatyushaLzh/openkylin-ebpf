package collector

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// scenarioHealthSnapshot reads cumulative kernel counters.  Program runtime
// fields are populated when BPF runtime stats are enabled by the host; zero is
// a valid "not enabled" value, not an invented estimate.
func scenarioHealthSnapshot(programs []*ebpf.Program, maps []*ebpf.Map, counterMap *ebpf.Map, counterNames []string) (HealthSnapshot, error) {
	out := HealthSnapshot{Counters: make(map[string]uint64, len(counterNames)+1)}
	mapMemoryEstimated := false
	for _, program := range programs {
		if program == nil {
			continue
		}
		info, err := program.Info()
		if err != nil {
			return out, fmt.Errorf("program info: %w", err)
		}
		if runtime, ok := info.Runtime(); ok {
			out.ProgramRuntimeNS += uint64(runtime.Nanoseconds())
		}
		if count, ok := info.RunCount(); ok {
			out.ProgramRunCount += count
		}
	}
	for _, m := range maps {
		if m == nil {
			continue
		}
		bytes, exact, err := mapMemlockBytes(m)
		if err != nil {
			return out, err
		}
		out.MapMemoryBytes += bytes
		mapMemoryEstimated = mapMemoryEstimated || !exact
	}
	for index, name := range counterNames {
		var value uint64
		if err := counterMap.Lookup(uint32(index), &value); err != nil {
			return out, fmt.Errorf("read health counter %s: %w", name, err)
		}
		out.Counters[name] = value
	}
	if mapMemoryEstimated {
		out.Counters["map_memory_estimated"] = 1
	} else {
		out.Counters["map_memory_estimated"] = 0
	}
	return out, nil
}

func (c *MemCollector) HealthSnapshot() (HealthSnapshot, error) {
	return scenarioHealthSnapshot(
		[]*ebpf.Program{c.objs.HandleDirectBegin, c.objs.HandleDirectEnd, c.objs.HandleKswapdWake, c.objs.HandleMarkVictim},
		[]*ebpf.Map{c.objs.Health, c.objs.KswapdWakes, c.objs.MemStats, c.objs.ObservedTgids, c.objs.OomStats, c.objs.ReclaimStart, c.objs.StartupTids, c.objs.TargetPid, c.objs.TargetTgids},
		c.objs.Health,
		[]string{"reclaim_start_update_fail", "reclaim_end_miss", "map_update_fail", "oom_update_fail", "target_update_fail"},
	)
}

func (c *LockCollector) HealthSnapshot() (HealthSnapshot, error) {
	return scenarioHealthSnapshot(
		[]*ebpf.Program{c.objs.HandleFutexEnter, c.objs.HandleFutexExit, c.objs.HandleSwitch, c.objs.HandleWakeup, c.objs.HandleWakeupNew},
		[]*ebpf.Map{c.objs.FutexActive, c.objs.Health, c.objs.LockStats, c.objs.LockStatZero, c.objs.ObservedTgids, c.objs.OffcpuStart, c.objs.Stackmap, c.objs.TargetPid, c.objs.TargetTgids},
		c.objs.Health,
		[]string{"futex_update_fail", "offcpu_update_fail", "map_update_fail", "stack_capture_fail", "target_update_fail"},
	)
}

func (c *SyscallCollector) HealthSnapshot() (HealthSnapshot, error) {
	return scenarioHealthSnapshot(
		[]*ebpf.Program{c.objs.HandleEnter, c.objs.HandleExit},
		[]*ebpf.Map{c.objs.Health, c.objs.ObservedTgids, c.objs.Start, c.objs.StartupTids, c.objs.SyscallStats, c.objs.TargetPid, c.objs.TargetTgids},
		c.objs.Health,
		[]string{"start_update_fail", "exit_miss", "map_update_fail", "target_update_fail"},
	)
}
