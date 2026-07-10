package collector

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

type targetTracker struct {
	root          uint32
	rootStart     uint64
	initialized   bool
	rootAlive     bool
	activeTGIDs   map[uint32]struct{}
	activeStarts  map[uint32]uint64
	retiredTGIDs  map[uint32]int
	retiredStarts map[uint32]uint64
	observedTGIDs map[uint32]observedTarget
	activeTIDs    map[uint32]struct{}
	retiredTIDs   map[uint32]int
}

type observedTarget struct {
	remaining int
	bpfStart  uint64
	procStart uint64
}

type observedTGIDEntry struct {
	tgid  uint32
	start uint64
}

// Linux exposes /proc/<pid>/stat starttime in USER_HZ ticks. USER_HZ is 100 on
// the supported Linux x86_64, arm64 and riscv64 ABIs; task_struct.start_boottime
// is nanoseconds in the same boot-time clock domain.
const linuxUserHZ = uint64(100)

const (
	targetProcStartSeedFlag = uint64(1) << 63
	targetProcStartSeedMask = targetProcStartSeedFlag - 1
)

func encodeProcStartSeed(procTicks uint64) uint64 {
	return targetProcStartSeedFlag | (procTicks & targetProcStartSeedMask)
}

// targetIdentityMatches mirrors the BPF seed/exact comparison. Exact
// start_boottime values are nanoseconds. Seed values carry /proc starttime in
// USER_HZ ticks and tolerate one tick because /proc quantizes the kernel value.
func targetIdentityMatches(stored, bpfStartNS uint64) bool {
	if stored == 0 || bpfStartNS == 0 {
		return false
	}
	if stored&targetProcStartSeedFlag == 0 {
		return stored == bpfStartNS
	}
	return procStartMatchesBPF(stored&targetProcStartSeedMask, bpfStartNS)
}

func procStartMatchesBPF(procTicks, bpfStartNS uint64) bool {
	seconds := bpfStartNS / uint64(1_000_000_000)
	remainder := bpfStartNS % uint64(1_000_000_000)
	bpfTicks := seconds*linuxUserHZ + remainder*linuxUserHZ/uint64(1_000_000_000)
	if procTicks > bpfTicks {
		return procTicks-bpfTicks <= 1
	}
	return bpfTicks-procTicks <= 1
}

func newTargetTracker(root uint32) *targetTracker {
	return &targetTracker{
		root: root, activeStarts: make(map[uint32]uint64),
		retiredTGIDs: make(map[uint32]int), retiredStarts: make(map[uint32]uint64),
		observedTGIDs: make(map[uint32]observedTarget), retiredTIDs: make(map[uint32]int),
	}
}

func (t *targetTracker) enabled() bool {
	return t != nil && t.root != 0
}

// initialize binds a directed observation to one process instance, not merely
// a reusable numeric PID. Constructors call this before loading BPF objects so
// a missing --target-pid fails instead of producing a healthy empty result.
func (t *targetTracker) initialize() error {
	if !t.enabled() {
		return nil
	}
	start, err := readProcStartTime(t.root)
	if err != nil {
		return fmt.Errorf("target pid %d is not a live readable process: %w", t.root, err)
	}
	t.rootStart = start
	t.initialized = true
	t.refresh()
	if _, ok := t.activeTGIDs[t.root]; !ok {
		return fmt.Errorf("target pid %d disappeared during initialization", t.root)
	}
	return nil
}

func (t *targetTracker) refresh() {
	if !t.enabled() {
		return
	}
	snap := readProcTreeSnapshot()
	tgids := make(map[uint32]struct{})
	start, startErr := readProcStartTime(t.root)
	t.rootAlive = t.initialized && startErr == nil && start == t.rootStart
	if t.rootAlive {
		if _, ok := snap[t.root]; ok {
			tgids = collectTargetTGIDs(t.root, snap)
		}
	}
	freshStarts := make(map[uint32]uint64, len(tgids))
	for tgid := range tgids {
		start, err := readProcStartTime(tgid)
		if err != nil {
			// A child can exit between the process-tree and identity snapshots.
			// The BPF ancestry path still captures its event-scoped identity.
			delete(tgids, tgid)
			continue
		}
		freshStarts[tgid] = start
	}
	tids := make(map[uint32]struct{}, len(tgids))
	for tgid := range tgids {
		taskIDs, err := readTaskIDs(tgid)
		if err != nil {
			tids[tgid] = struct{}{}
			continue
		}
		for _, tid := range taskIDs {
			tids[tid] = struct{}{}
		}
	}
	oldActive := t.activeTGIDs
	oldStarts := t.activeStarts
	t.activeTGIDs, t.retiredTGIDs = advanceTargetMembership(t.activeTGIDs, t.retiredTGIDs, tgids)
	for id := range oldActive {
		if _, active := tgids[id]; active {
			continue
		}
		if _, retired := t.retiredTGIDs[id]; retired {
			t.retiredStarts[id] = oldStarts[id]
		}
	}
	t.activeStarts = freshStarts
	for id := range tgids {
		delete(t.retiredStarts, id)
	}
	for id := range t.retiredStarts {
		if _, retired := t.retiredTGIDs[id]; !retired {
			delete(t.retiredStarts, id)
		}
	}
	for id := range t.retiredTGIDs {
		expected, bound := t.retiredStarts[id]
		if !bound || expected == 0 {
			delete(t.retiredTGIDs, id)
			delete(t.retiredStarts, id)
			continue
		}
		if current, err := readProcStartTime(id); err == nil && current != expected {
			// The numeric PID now names an unrelated process; drain grace applies
			// only to the original process instance.
			delete(t.retiredTGIDs, id)
			delete(t.retiredStarts, id)
		}
	}
	t.activeTIDs, t.retiredTIDs = advanceTargetMembership(t.activeTIDs, t.retiredTIDs, tids)
	if !t.rootAlive {
		// The numeric root is unsafe once its starttime no longer matches; do
		// not apply ordinary drain grace to a PID that may already be reused.
		delete(t.retiredTGIDs, t.root)
		delete(t.retiredStarts, t.root)
		delete(t.observedTGIDs, t.root)
	}
	for id, observed := range t.observedTGIDs {
		if _, active := t.activeTGIDs[id]; active {
			delete(t.observedTGIDs, id)
			continue
		}
		if current, err := readProcStartTime(id); err == nil {
			if !procStartMatchesBPF(current, observed.bpfStart) ||
				(observed.procStart != 0 && current != observed.procStart) {
				delete(t.observedTGIDs, id)
				continue
			}
			observed.procStart = current
		}
		if observed.remaining <= 1 {
			delete(t.observedTGIDs, id)
		} else {
			observed.remaining--
			t.observedTGIDs[id] = observed
		}
	}
}

func (t *targetTracker) observeTGID(tgid uint32, bpfStart uint64) {
	if !t.enabled() || tgid == 0 || bpfStart == 0 {
		return
	}
	if tgid == t.root && !t.rootAlive {
		// A queued heartbeat for the old root instance must not resurrect a
		// numeric PID after starttime identity has been lost.
		return
	}
	if _, active := t.activeTGIDs[tgid]; active {
		return
	}
	observed := observedTarget{remaining: staleWindowsBeforeDelete, bpfStart: bpfStart}
	if old, ok := t.observedTGIDs[tgid]; ok && old.bpfStart == bpfStart {
		observed.procStart = old.procStart
	}
	if current, err := readProcStartTime(tgid); err == nil {
		if !procStartMatchesBPF(current, bpfStart) ||
			(observed.procStart != 0 && current != observed.procStart) {
			return
		}
		observed.procStart = current
	}
	t.observedTGIDs[tgid] = observed
}

// bpfFilterRoot disables ancestry discovery with an impossible PID after the
// original root instance exits. Existing admitted children remain in the
// explicit membership map for their drain grace, but PID reuse cannot retarget
// the session.
func (t *targetTracker) bpfFilterRoot() uint32 {
	if !t.enabled() {
		return 0
	}
	if t.rootAlive {
		return t.root
	}
	return ^uint32(0)
}

func readProcStartTime(pid uint32) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	text := string(b)
	rightParen := strings.LastIndexByte(text, ')')
	if rightParen < 0 || rightParen+2 >= len(text) {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	// Fields after comm start at field 3 (state); starttime is field 22.
	fields := strings.Fields(text[rightParen+2:])
	if len(fields) <= 19 {
		return 0, fmt.Errorf("stat for pid %d has no starttime", pid)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse starttime for pid %d: %w", pid, err)
	}
	return start, nil
}

func advanceTargetMembership(active map[uint32]struct{}, retired map[uint32]int,
	fresh map[uint32]struct{}) (map[uint32]struct{}, map[uint32]int) {
	if retired == nil {
		retired = make(map[uint32]int)
	}
	for id, remaining := range retired {
		if remaining <= 1 {
			delete(retired, id)
		} else {
			retired[id] = remaining - 1
		}
	}
	for id := range active {
		if _, stillActive := fresh[id]; !stillActive {
			retired[id] = staleWindowsBeforeDelete
		}
	}
	for id := range fresh {
		delete(retired, id)
	}
	return fresh, retired
}

func (t *targetTracker) containsTGID(pid uint32) bool {
	if !t.enabled() {
		return true
	}
	if pid == 0 {
		return false
	}
	if _, ok := t.activeTGIDs[pid]; ok {
		return true
	}
	if observed, ok := t.observedTGIDs[pid]; ok {
		if current, err := readProcStartTime(pid); err == nil {
			return observed.procStart != 0 && current == observed.procStart &&
				procStartMatchesBPF(current, observed.bpfStart)
		}
		return true
	}
	if _, ok := t.retiredTGIDs[pid]; ok {
		expected := t.retiredStarts[pid]
		if current, err := readProcStartTime(pid); err == nil {
			return expected != 0 && current == expected
		}
		return expected != 0
	}
	return false
}

func (t *targetTracker) containsTID(tid uint32) bool {
	if !t.enabled() {
		return true
	}
	if tid == 0 {
		return false
	}
	if _, ok := t.activeTIDs[tid]; ok {
		return true
	}
	_, ok := t.retiredTIDs[tid]
	return ok
}

func (t *targetTracker) targetTGIDs() []uint32 {
	if !t.enabled() {
		return nil
	}
	seeds := t.targetTGIDSeeds()
	out := make([]uint32, 0, len(seeds))
	for pid := range seeds {
		out = append(out, pid)
	}
	return out
}

// targetTGIDSeeds binds every /proc-discovered active/retired member to its
// quantized process instance. BPF-observed members already carry an exact
// start_boottime and therefore keep the stronger identity.
func (t *targetTracker) targetTGIDSeeds() map[uint32]uint64 {
	desired := make(map[uint32]uint64, len(t.activeTGIDs)+len(t.retiredTGIDs)+len(t.observedTGIDs))
	if !t.enabled() {
		return desired
	}
	for pid := range t.activeTGIDs {
		desired[pid] = encodeProcStartSeed(t.activeStarts[pid])
	}
	for pid := range t.retiredTGIDs {
		if _, active := t.activeTGIDs[pid]; !active && t.containsTGID(pid) {
			desired[pid] = encodeProcStartSeed(t.retiredStarts[pid])
		}
	}
	for pid, observed := range t.observedTGIDs {
		if _, active := t.activeTGIDs[pid]; active {
			continue
		}
		if _, retired := t.retiredTGIDs[pid]; retired {
			continue
		}
		if t.containsTGID(pid) {
			desired[pid] = observed.bpfStart
		}
	}
	return desired
}

func drainObservedTGIDs(observed *ebpf.Map, target *targetTracker) error {
	if target == nil || !target.enabled() || observed == nil {
		return nil
	}
	var entries []observedTGIDEntry
	var key uint32
	var value uint64
	it := observed.Iterate()
	for it.Next(&key, &value) {
		// Map iteration reuses key/value storage, so copy the pair now. Keeping
		// only the keys would accidentally apply the final entry's process
		// identity to every TGID in this drain batch.
		entries = append(entries, observedTGIDEntry{tgid: key, start: value})
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate BPF-observed target tgids: %w", err)
	}
	applyObservedTGIDEntries(entries, target.observeTGID)
	for _, entry := range entries {
		if err := observed.Delete(entry.tgid); err != nil && !isKeyNotExist(err) {
			return fmt.Errorf("drain BPF-observed target tgid %d: %w", entry.tgid, err)
		}
	}
	return nil
}

func applyObservedTGIDEntries(entries []observedTGIDEntry, observe func(uint32, uint64)) {
	for _, entry := range entries {
		observe(entry.tgid, entry.start)
	}
}

// syncTargetTGIDMap preserves exact BPF start_boottime identities that match
// the desired /proc seed. New members receive a marked USER_HZ seed, so even a
// process deeper than the bounded BPF ancestry walk can pass instance matching
// and upgrade itself to an exact identity on its first light-weight hook.
func syncTargetTGIDMap(targetMap *ebpf.Map, desired map[uint32]uint64) error {
	if targetMap == nil {
		return fmt.Errorf("target tgid map is unavailable")
	}
	present := make(map[uint32]struct{}, len(desired))
	var key uint32
	var identity uint64
	it := targetMap.Iterate()
	for it.Next(&key, &identity) {
		wanted, ok := desired[key]
		if !ok {
			if err := targetMap.Delete(key); err != nil && !isKeyNotExist(err) {
				return fmt.Errorf("delete stale target tgid %d: %w", key, err)
			}
			continue
		}
		if targetMapIdentityMatchesDesired(identity, wanted) {
			present[key] = struct{}{}
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate target tgids: %w", err)
	}
	for tgid, wanted := range desired {
		if _, ok := present[tgid]; ok {
			continue
		}
		// Recheck after iteration: a BPF hook may have upgraded the seed to an
		// exact identity while user space was walking the map.
		var current uint64
		if err := targetMap.Lookup(tgid, &current); err == nil &&
			targetMapIdentityMatchesDesired(current, wanted) {
			continue
		} else if err != nil && !isKeyNotExist(err) {
			return fmt.Errorf("recheck target tgid %d: %w", tgid, err)
		}
		if err := targetMap.Put(tgid, wanted); err != nil {
			return fmt.Errorf("insert target tgid %d: %w", tgid, err)
		}
	}
	return nil
}

func targetMapIdentityMatchesDesired(current, desired uint64) bool {
	if desired&targetProcStartSeedFlag == 0 {
		return current == desired
	}
	if current&targetProcStartSeedFlag != 0 {
		return current == desired
	}
	return targetIdentityMatches(desired, current)
}

func seedStartupTIDs(startup *ebpf.Map) error {
	if startup == nil {
		return fmt.Errorf("startup tid map is unavailable")
	}
	one := uint8(1)
	seen := make(map[uint32]struct{})
	for tgid := range readProcTreeSnapshot() {
		tids, err := readTaskIDs(tgid)
		if err != nil {
			// Process exit races are expected while walking /proc.
			continue
		}
		for _, tid := range tids {
			if _, duplicate := seen[tid]; duplicate {
				continue
			}
			seen[tid] = struct{}{}
			if err := startup.Put(tid, one); err != nil {
				return fmt.Errorf("seed startup tid %d: %w", tid, err)
			}
		}
	}
	return nil
}

func isKeyNotExist(err error) bool {
	return err == nil || errors.Is(err, ebpf.ErrKeyNotExist)
}

type procTreeInfo struct {
	ppid uint32
}

func readProcTreeSnapshot() map[uint32]procTreeInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make(map[uint32]procTreeInfo, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		ppid, err := readProcPPID(pid)
		if err != nil {
			continue
		}
		out[pid] = procTreeInfo{ppid: ppid}
	}
	return out
}

func collectTargetTGIDs(root uint32, snap map[uint32]procTreeInfo) map[uint32]struct{} {
	children := make(map[uint32][]uint32)
	for pid, info := range snap {
		children[info.ppid] = append(children[info.ppid], pid)
	}
	seen := map[uint32]struct{}{root: {}}
	queue := []uint32{root}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, child := range children[pid] {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			queue = append(queue, child)
		}
	}
	return seen
}

func readProcPPID(pid uint32) (uint32, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed PPid line for pid %d", pid)
		}
		ppid64, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, err
		}
		return uint32(ppid64), nil
	}
	return 0, fmt.Errorf("PPid not found for pid %d", pid)
}

func readTaskIDs(pid uint32) ([]uint32, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		tid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		out = append(out, uint32(tid64))
	}
	return out, nil
}
