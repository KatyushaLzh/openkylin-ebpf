package collector

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// bpfObjectMetrics returns cumulative program counters and map memory.  The
// boolean result is true if at least one map had to use the logical-capacity
// fallback instead of an exact fdinfo memlock charge.
func bpfObjectMetrics(programs []*ebpf.Program, maps []*ebpf.Map) (uint64, uint64, uint64, bool, error) {
	var runtimeNS, runCount, mapBytes uint64
	mapMemoryEstimated := false
	for _, prog := range programs {
		if prog == nil {
			continue
		}
		info, err := prog.Info()
		if err != nil {
			return 0, 0, 0, false, fmt.Errorf("read BPF program info: %w", err)
		}
		if runtime, ok := info.Runtime(); ok && runtime > 0 {
			runtimeNS += uint64(runtime.Nanoseconds())
		}
		if count, ok := info.RunCount(); ok {
			runCount += count
		}
	}
	for _, m := range maps {
		if m == nil {
			continue
		}
		bytes, exact, err := mapMemlockBytes(m)
		if err != nil {
			return 0, 0, 0, false, err
		}
		mapBytes += bytes
		mapMemoryEstimated = mapMemoryEstimated || !exact
	}
	return runtimeNS, runCount, mapBytes, mapMemoryEstimated, nil
}

func mapMemlockBytes(m *ebpf.Map) (uint64, bool, error) {
	f, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", m.FD()))
	if err == nil {
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 2 && fields[0] == "memlock:" {
				bytes, parseErr := strconv.ParseUint(fields[1], 10, 64)
				if parseErr != nil {
					return 0, false, fmt.Errorf("parse map memlock: %w", parseErr)
				}
				return bytes, true, nil
			}
		}
		if scanErr := sc.Err(); scanErr != nil {
			return 0, false, fmt.Errorf("scan map fdinfo: %w", scanErr)
		}
	}

	info, infoErr := m.Info()
	if infoErr != nil {
		return 0, false, fmt.Errorf("read BPF map info: %w", infoErr)
	}
	return uint64(info.KeySize+info.ValueSize) * uint64(info.MaxEntries), false, nil
}

func (c *CPUCollector) HealthSnapshot() (HealthSnapshot, error) {
	runtimeNS, runCount, mapBytes, mapMemoryEstimated, err := bpfObjectMetrics(
		[]*ebpf.Program{c.objs.HandleSeedOncpu, c.objs.HandleSwitch, c.objs.HandleWakeup, c.objs.HandleWakeupNew},
		[]*ebpf.Map{c.objs.EnqueueTs, c.objs.Health, c.objs.OncpuStart,
			c.objs.StackStats, c.objs.Stats, c.objs.UserStacks},
	)
	if err != nil {
		return HealthSnapshot{}, err
	}
	var h cpuHealthStat
	if err := c.objs.Health.Lookup(uint32(0), &h); err != nil {
		return HealthSnapshot{}, fmt.Errorf("read CPU health map: %w", err)
	}
	statsUnavailable := uint64(0)
	if !c.statsReady {
		statsUnavailable = 1
	}
	estimated := uint64(0)
	if mapMemoryEstimated {
		estimated = 1
	}
	return HealthSnapshot{
		ProgramRuntimeNS: runtimeNS,
		ProgramRunCount:  runCount,
		MapMemoryBytes:   mapBytes,
		Counters: map[string]uint64{
			"map_update_fail":           h.MapUpdateFail,
			"map_memory_estimated":      estimated,
			"stack_capture_fail":        h.StackCaptureFail,
			"program_stats_unavailable": statsUnavailable,
		},
	}, nil
}

func (c *IOCollector) HealthSnapshot() (HealthSnapshot, error) {
	runtimeNS, runCount, mapBytes, mapMemoryEstimated, err := bpfObjectMetrics(
		[]*ebpf.Program{c.objs.HandleIssue, c.objs.HandleComplete},
		[]*ebpf.Map{c.objs.StartupBoundaryNs, c.objs.DevStats, c.objs.Health, c.objs.Start},
	)
	if err != nil {
		return HealthSnapshot{}, err
	}
	var h ioHealthStat
	if err := c.objs.Health.Lookup(uint32(0), &h); err != nil {
		return HealthSnapshot{}, fmt.Errorf("read I/O health map: %w", err)
	}
	statsUnavailable := uint64(0)
	if !c.statsReady {
		statsUnavailable = 1
	}
	estimated := uint64(0)
	if mapMemoryEstimated {
		estimated = 1
	}
	return HealthSnapshot{
		ProgramRuntimeNS: runtimeNS,
		ProgramRunCount:  runCount,
		MapMemoryBytes:   mapBytes,
		Counters: map[string]uint64{
			"duplicate_issue":           h.DuplicateIssue,
			"completion_miss":           h.CompletionMiss,
			"map_memory_estimated":      estimated,
			"map_update_fail":           h.MapUpdateFail,
			"partial_completion":        h.PartialCompletion,
			"io_error":                  h.IOError,
			"current_inflight":          c.lastInflight,
			"average_queue_depth_milli": c.lastAverageQueueDepthMilli,
			"program_stats_unavailable": statsUnavailable,
		},
	}, nil
}
