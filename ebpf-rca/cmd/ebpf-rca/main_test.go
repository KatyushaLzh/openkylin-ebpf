package main

import "testing"

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
