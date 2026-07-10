package collector

import (
	"os"
	"testing"
	"time"
)

func TestAdvanceTargetMembershipDrainsExitedProcessesThenExpires(t *testing.T) {
	active := map[uint32]struct{}{10: {}, 11: {}}
	retired := map[uint32]int{}
	fresh := map[uint32]struct{}{10: {}}

	active, retired = advanceTargetMembership(active, retired, fresh)
	if _, ok := retired[11]; !ok {
		t.Fatal("exited child must remain during drain grace")
	}
	for i := 0; i < staleWindowsBeforeDelete; i++ {
		active, retired = advanceTargetMembership(active, retired, fresh)
	}
	if _, ok := retired[11]; ok {
		t.Fatal("retired child did not expire")
	}
}

func TestTargetTrackerFailsClosedWhenNoMembershipRemains(t *testing.T) {
	tracker := newTargetTracker(999)
	if tracker.containsTGID(999) {
		t.Fatal("an absent/reused root PID must not be implicitly accepted")
	}
	if got := tracker.targetTGIDs(); len(got) != 0 {
		t.Fatalf("empty membership=%v, want none", got)
	}
}

func TestTargetTrackerInitializationBindsProcessInstance(t *testing.T) {
	missing := newTargetTracker(^uint32(0))
	if err := missing.initialize(); err == nil {
		t.Fatal("a nonexistent target PID must fail initialization")
	}

	pid := uint32(os.Getpid())
	tracker := newTargetTracker(pid)
	if err := tracker.initialize(); err != nil {
		t.Fatalf("initialize current process target: %v", err)
	}
	if !tracker.containsTGID(pid) || tracker.rootStart == 0 {
		t.Fatalf("live target instance not captured: %+v", tracker)
	}

	// Simulate that the configured numeric PID now identifies another process.
	tracker.rootStart++
	tracker.refresh()
	if _, active := tracker.activeTGIDs[pid]; active {
		t.Fatal("PID reuse must not retarget the active process tree")
	}
	if tracker.bpfFilterRoot() != ^uint32(0) {
		t.Fatal("BPF ancestry discovery must be disabled after root identity loss")
	}
	tracker.observeTGID(pid, 1)
	if tracker.containsTGID(pid) {
		t.Fatal("a queued BPF heartbeat must not resurrect a reused root PID")
	}
	for _, got := range tracker.targetTGIDs() {
		if got == pid {
			t.Fatal("reused root PID remained in BPF target membership")
		}
	}
}

func TestTargetTrackerRetainsBPFObservedShortLivedChild(t *testing.T) {
	tracker := newTargetTracker(uint32(os.Getpid()))
	if err := tracker.initialize(); err != nil {
		t.Fatal(err)
	}
	const child = uint32(4_000_001)
	tracker.observeTGID(child, 12345)
	if !tracker.containsTGID(child) {
		t.Fatal("BPF-observed child must be admitted immediately")
	}
	for i := 0; i < staleWindowsBeforeDelete; i++ {
		tracker.refresh()
	}
	if tracker.containsTGID(child) {
		t.Fatal("BPF-observed child did not expire after drain grace")
	}
}

func TestTargetTrackerRejectsReusedObservedAndRetiredTGID(t *testing.T) {
	pid := uint32(os.Getpid())
	start, err := readProcStartTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	tracker := newTargetTracker(1)
	tracker.observedTGIDs[pid] = observedTarget{
		remaining: staleWindowsBeforeDelete,
		bpfStart:  100,
		procStart: start + 1,
	}
	if tracker.containsTGID(pid) {
		t.Fatal("observed membership must be bound to the original process instance")
	}
	delete(tracker.observedTGIDs, pid)
	tracker.retiredTGIDs[pid] = staleWindowsBeforeDelete
	tracker.retiredStarts[pid] = start + 1
	if tracker.containsTGID(pid) {
		t.Fatal("retired drain grace must not admit a reused numeric PID")
	}
}

func TestProcStartMatchesBPFClockDomains(t *testing.T) {
	const ticks = uint64(123456)
	ns := ticks * uint64(time.Second) / linuxUserHZ
	if !procStartMatchesBPF(ticks, ns+5_000_000) {
		t.Fatal("sub-tick BPF start time must match /proc clock ticks")
	}
	if procStartMatchesBPF(ticks+10, ns) {
		t.Fatal("different process start times must not match")
	}
}

func TestTargetIdentitySeedEncodingAndMatching(t *testing.T) {
	const ticks = uint64(123456)
	seed := encodeProcStartSeed(ticks)
	if seed&targetProcStartSeedFlag == 0 || seed&targetProcStartSeedMask != ticks {
		t.Fatalf("encoded seed=%#x", seed)
	}
	ns := ticks * uint64(time.Second) / linuxUserHZ
	if !targetIdentityMatches(seed, ns+5_000_000) {
		t.Fatal("marked /proc seed must match its quantized BPF start_boottime")
	}
	if targetIdentityMatches(seed, ns+30_000_000) {
		t.Fatal("marked /proc seed admitted a different process instance")
	}
	if !targetIdentityMatches(ns, ns) || targetIdentityMatches(ns, ns+1) {
		t.Fatal("exact BPF identities must use exact equality")
	}
	if !targetMapIdentityMatchesDesired(ns+5_000_000, seed) {
		t.Fatal("a matching exact identity should be preserved over a seed")
	}
}

func TestTargetMissingExitRequiresCurrentProcessInstance(t *testing.T) {
	const oldTicks = uint64(50_000)
	oldExact := oldTicks * uint64(time.Second) / linuxUserHZ
	seed := encodeProcStartSeed(oldTicks)
	if !targetIdentityMatches(oldExact, oldExact) || !targetIdentityMatches(seed, oldExact) {
		t.Fatal("the admitted process instance must classify a missing exit as loss")
	}
	reusedExact := oldExact + 100*uint64(time.Millisecond)
	if targetIdentityMatches(oldExact, reusedExact) || targetIdentityMatches(seed, reusedExact) {
		t.Fatal("a reused numeric PID must not classify its untracked exit as target data loss")
	}
}

func TestDeepTargetTreeReceivesInstanceSeeds(t *testing.T) {
	const depth = uint32(20)
	snap := make(map[uint32]procTreeInfo, depth)
	snap[1] = procTreeInfo{ppid: 0}
	for pid := uint32(2); pid <= depth; pid++ {
		snap[pid] = procTreeInfo{ppid: pid - 1}
	}
	members := collectTargetTGIDs(1, snap)
	if _, ok := members[depth]; !ok {
		t.Fatalf("depth-%d descendant missing from /proc BFS", depth)
	}
	tracker := newTargetTracker(1)
	tracker.activeTGIDs = members
	tracker.activeStarts = make(map[uint32]uint64, len(members))
	for pid := range members {
		tracker.activeStarts[pid] = 10_000 + uint64(pid)
	}
	seeds := tracker.targetTGIDSeeds()
	deepSeed := seeds[depth]
	deepNS := tracker.activeStarts[depth] * uint64(time.Second) / linuxUserHZ
	if deepSeed&targetProcStartSeedFlag == 0 || !targetIdentityMatches(deepSeed, deepNS) {
		t.Fatalf("deep descendant seed=%#x does not bind its instance", deepSeed)
	}
}

func TestObservedTGIDBatchPreservesPerProcessIdentity(t *testing.T) {
	entries := []observedTGIDEntry{
		{tgid: 101, start: 11_000_000},
		{tgid: 202, start: 22_000_000},
	}
	got := make(map[uint32]uint64)
	applyObservedTGIDEntries(entries, func(tgid uint32, start uint64) {
		got[tgid] = start
	})
	if got[101] != 11_000_000 || got[202] != 22_000_000 {
		t.Fatalf("observed identities were cross-assigned: %#v", got)
	}
}
