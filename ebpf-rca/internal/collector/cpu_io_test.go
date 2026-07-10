package collector

import (
	"reflect"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	got, err := parseCPUList("0-3,8,10-11\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 1, 2, 3, 8, 10, 11}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCPUList = %v, want %v", got, want)
	}
	for _, invalid := range []string{"", "3-1", "x", "1-2-3"} {
		if _, err := parseCPUList(invalid); err == nil {
			t.Fatalf("parseCPUList(%q) must fail", invalid)
		}
	}
}

func TestIOHistogramUsesBucketUpperBound(t *testing.T) {
	var cur, prev [ioNSlots]uint64
	// floor(log2(10ms)) == 23, whose upper bound is 2^24-1 ns.
	cur[23] = 100
	want := float64((uint64(1)<<24)-1) / 1e6
	if got := p99FromSlots(cur, prev, 100); got != want {
		t.Fatalf("p99=%f, want bucket upper %f", got, want)
	}
	if got := maxNSFromIOSlots(cur, prev); got != (uint64(1)<<24)-1 {
		t.Fatalf("max=%d", got)
	}
}

func TestModuleOffsetIncludesFileOffset(t *testing.T) {
	mappings := []procMapping{{start: 0x7000, end: 0x8000, fileOffset: 0x2000, module: "libx.so"}}
	if got := moduleOffset(0x7123, mappings); got != "libx.so+0x2123" {
		t.Fatalf("module offset=%q", got)
	}
}

func TestCounterDeltaHandlesEntryReplacement(t *testing.T) {
	if got := counterDelta(3, 100); got != 3 {
		t.Fatalf("delta after reset=%d, want 3", got)
	}
}

func TestLiveRunDeltaRepaysSyntheticRuntimeWithoutDoubleCounting(t *testing.T) {
	c := &CPUCollector{liveRuns: make(map[taskKey]liveRunCredit)}
	key := taskKey{Tgid: 10, Tid: 11}
	running := oncpuInfo{Task: key, StartNs: 100}

	if got := c.liveRunDelta(key, 0, 0, running, true, 200); got != 100 {
		t.Fatalf("first live delta=%d, want 100", got)
	}
	if got := c.liveRunDelta(key, 0, 0, running, true, 260); got != 60 {
		t.Fatalf("continued live delta=%d, want 60", got)
	}
	// sched_switch commits the whole 160ns interval. It has already been
	// reported synthetically, so the completed cumulative delta contributes 0.
	if got := c.liveRunDelta(key, 160, 0, oncpuInfo{}, false, 300); got != 0 {
		t.Fatalf("repaid completed delta=%d, want 0", got)
	}
}

func TestLiveRunDeltaCarriesDebtAcrossSplitMapRace(t *testing.T) {
	c := &CPUCollector{liveRuns: make(map[taskKey]liveRunCredit)}
	key := taskKey{Tgid: 20, Tid: 21}
	first := oncpuInfo{Task: key, StartNs: 100}
	if got := c.liveRunDelta(key, 0, 0, first, true, 200); got != 100 {
		t.Fatalf("first live delta=%d, want 100", got)
	}
	// stats was read before switch-out and oncpu_start after deletion: no
	// cumulative delta is visible yet, but the debt must survive.
	if got := c.liveRunDelta(key, 0, 0, oncpuInfo{}, false, 220); got != 0 {
		t.Fatalf("split snapshot delta=%d, want 0", got)
	}
	if got := c.liveRunDelta(key, 120, 0, oncpuInfo{}, false, 240); got != 20 {
		t.Fatalf("delayed cumulative delta=%d, want only unreported 20", got)
	}
}
