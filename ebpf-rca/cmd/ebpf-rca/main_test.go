package main

import (
	"errors"
	"math"
	"testing"

	"github.com/KatyushaLzh/openkylin-ebpf/ebpf-rca/internal/collector"
)

func TestBuildThresholdsLegacySingleScenario(t *testing.T) {
	th, err := buildThresholds("io", 7, true, defaultThresholds)
	if err != nil {
		t.Fatal(err)
	}
	if th.IOP99Ms != 7 {
		t.Fatalf("io threshold = %v, want 7", th.IOP99Ms)
	}
	if th.CPU != defaultThresholds.CPU {
		t.Fatalf("cpu threshold changed unexpectedly: %v", th.CPU)
	}
}

func TestValidateThresholdsRejectsNonFiniteNegativeAndInvalidPercent(t *testing.T) {
	for _, th := range []thresholds{
		{CPU: math.NaN()},
		{CPU: -0.1},
		{MemAvailFloorPct: 101},
	} {
		if err := validateThresholds(th); err == nil {
			t.Fatalf("expected invalid thresholds to fail: %+v", th)
		}
	}
	if err := validateThresholds(defaultThresholds); err != nil {
		t.Fatalf("default thresholds: %v", err)
	}
}

func TestBuildThresholdsRejectsLegacyAll(t *testing.T) {
	if _, err := buildThresholds("all", 0.8, true, defaultThresholds); err == nil {
		t.Fatal("expected all + --threshold to fail")
	}
}

func TestPrepareLockSamplesFiltersNonLockStacksByDefault(t *testing.T) {
	samples := []collector.LockSample{
		{Pid: 101, StackID: 1, OffcpuRatio: 0.9},
		{Pid: 102, StackID: 2, OffcpuRatio: 0.95},
	}
	resolve := func(id int32, _ int) []string {
		switch id {
		case 1:
			return []string{"schedule", "futex_wait_queue"}
		case 2:
			return []string{"schedule_timeout", "do_poll"}
		default:
			return nil
		}
	}
	got, stacks := prepareLockSamples(samples, resolve, lockConfig{topN: 5})
	if len(got) != 1 || got[0].Pid != 101 {
		t.Fatalf("default lock filter should keep only futex stack, got %#v", got)
	}
	if len(stacks[lockKeyOf(got[0])]) == 0 {
		t.Fatalf("expected resolved stack for kept sample")
	}
}

func TestPrepareLockSamplesKeepsFutexWithUnavailableSymbols(t *testing.T) {
	sample := collector.LockSample{Pid: 101, Tid: 102, LockAddress: 0x1234, Futex: true, StackID: -14, OffcpuRatio: 0.9}
	got, stacks := prepareLockSamples([]collector.LockSample{sample}, func(int32, int) []string { return nil }, lockConfig{topN: 5})
	if len(got) != 1 {
		t.Fatalf("futex address is authoritative even without kallsyms, got %#v", got)
	}
	if _, ok := stacks[lockKeyOf(sample)]; !ok {
		t.Fatal("missing instance-keyed stack entry")
	}
}

func TestPrepareLockSamplesIncludeBlockingAndTopN(t *testing.T) {
	samples := []collector.LockSample{
		{Pid: 101, StackID: 1, OffcpuRatio: 0.2, MaxOffcpuMs: 10},
		{Pid: 102, StackID: 2, OffcpuRatio: 0.9, MaxOffcpuMs: 20},
		{Pid: 103, StackID: 3, OffcpuRatio: 0.7, MaxOffcpuMs: 30},
	}
	resolve := func(id int32, _ int) []string {
		return []string{"schedule_timeout", "do_poll"}
	}
	got, _ := prepareLockSamples(samples, resolve, lockConfig{includeBlocking: true, topN: 2})
	if len(got) != 2 || got[0].Pid != 102 || got[1].Pid != 103 {
		t.Fatalf("expected top 2 by offcpu ratio, got %#v", got)
	}
}

func TestCollectorHealthFailureIsTerminal(t *testing.T) {
	tracker := newCollectorTracker("cpu")
	tracker.initialized("cpu")
	tracker.healthUnavailable(errors.New("runtime stats unavailable"))
	if err := tracker.failUnhealthy(); err == nil {
		t.Fatal("unreadable collector health must fail the session")
	}
	status := tracker.snapshot()[0]
	if status.State != "failed" || status.Error == "" || !tracker.partial {
		t.Fatalf("health failure did not become terminal: status=%+v partial=%t", status, tracker.partial)
	}
}

func TestHealthIntegrityCounters(t *testing.T) {
	if err := healthIntegrityError(map[string]uint64{"partial_completion": 7}); err != nil {
		t.Fatalf("partial completion is informational: %v", err)
	}
	if err := healthIntegrityError(map[string]uint64{"map_update_fail": 1}); err == nil {
		t.Fatal("map update loss must fail health validation")
	}
	if err := healthIntegrityError(map[string]uint64{"completion_miss": 1}); err == nil {
		t.Fatal("unmatched I/O completion must fail health validation")
	}
}
