package main

import (
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
	if len(stacks[101]) == 0 {
		t.Fatalf("expected resolved stack for kept sample")
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
