package collector

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type memStat struct {
	DirectReclaimCount uint64
	DirectReclaimNs    uint64
	Comm               [16]byte
}

type oomStat struct {
	Count    uint64
	UID      uint32
	InTarget uint8
	Pad      [3]byte
	Comm     [16]byte
}

type fault struct{ maj, min uint64 }
type rssSample struct{ rss, anon uint64 }
type psiSample struct{ someUS, fullUS uint64 }

type vmStatSample struct {
	PgscanDirect uint64
	PgscanKswapd uint64
	Pgsteal      uint64
	Pgmajfault   uint64
	OOMKill      uint64
}

const (
	// Rates, not raw per-window deltas.  This keeps the operating point stable
	// when --interval changes.
	MemAnonRSSGrowthSignalKBPerSec = 64 * 1024
	MemMajorFaultSignalPerSec      = 100.0
	MemDirectReclaimSignalMsPerSec = 10.0
	MemPSISomeSignalPct            = 10.0
	MemPSIFullSignalPct            = 1.0

	// Kept for source compatibility; new detection uses the per-second field.
	MemRSSGrowthSignalKB uint64 = MemAnonRSSGrowthSignalKBPerSec
)

type MemProc struct {
	Pid                   uint32
	Comm                  string
	DirectReclaimCount    uint64
	DirectReclaimMs       float64
	MajFlt                uint64
	MinFlt                uint64
	MajFltPerSec          float64
	RSSKB                 uint64
	AnonRSSKB             uint64
	RSSDeltaKB            uint64
	AnonRSSDeltaKB        uint64
	AnonRSSGrowthKBPerSec float64
	OOMVictimCount        uint64
}

type MemSnapshot struct {
	Window                ObservationWindow
	MemAvailablePct       float64
	MemTotalKB            uint64
	MemAvailableKB        uint64
	PSISomePct            float64
	PSIFullPct            float64
	DirectReclaimMsPerSec float64
	KswapdWakes           uint64
	PgscanDirect          uint64
	PgscanKswapd          uint64
	Pgsteal               uint64
	Pgmajfault            uint64
	VMStatOOMKills        uint64
	OOMVictimCount        uint64
	OOMVictims            []MemProc
	Procs                 []MemProc
	TopRSSProc            MemProc
	GlobalContribution    bool
	Targeted              bool
}

type MemCollector struct {
	objs       memObjects
	links      []link.Link
	prev       map[uint32]memStat
	prevOOM    map[uint32]oomStat
	prevFault  map[uint32]fault
	prevRSS    map[uint32]rssSample
	prevPSI    psiSample
	prevVM     vmStatSample
	prevKswapd uint64
	lastPollNS uint64
	psiPrimed  bool
	vmPrimed   bool
	procPrimed bool
	stale      map[uint32]int
	oomStale   map[uint32]int
	target     *targetTracker
	scanFloor  float64
}

func NewMemCollector(targetPID uint32, availableFloorPct ...float64) (*MemCollector, error) {
	target := newTargetTracker(targetPID)
	if err := target.initialize(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &MemCollector{
		prev:      make(map[uint32]memStat),
		prevOOM:   make(map[uint32]oomStat),
		prevFault: make(map[uint32]fault),
		prevRSS:   make(map[uint32]rssSample),
		stale:     make(map[uint32]int),
		oomStale:  make(map[uint32]int),
		target:    target,
		scanFloor: 15,
	}
	if len(availableFloorPct) > 0 {
		c.scanFloor = availableFloorPct[0]
	}
	if err := loadMemObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	if err := c.objs.TargetPid.Put(uint32(0), targetPID); err != nil {
		c.Close()
		return nil, fmt.Errorf("set target pid: %w", err)
	}
	if err := c.refreshTargetTGIDs(); err != nil {
		c.Close()
		return nil, err
	}

	begin, err := link.Tracepoint("vmscan", "mm_vmscan_direct_reclaim_begin", c.objs.HandleDirectBegin, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach direct_reclaim_begin: %w", err)
	}
	c.links = append(c.links, begin)
	if err := seedStartupTIDs(c.objs.StartupTids); err != nil {
		c.Close()
		return nil, fmt.Errorf("seed pre-attach reclaim tids: %w", err)
	}
	end, err := link.Tracepoint("vmscan", "mm_vmscan_direct_reclaim_end", c.objs.HandleDirectEnd, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach direct_reclaim_end: %w", err)
	}
	c.links = append(c.links, end)
	kw, err := link.Tracepoint("vmscan", "mm_vmscan_kswapd_wake", c.objs.HandleKswapdWake, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach kswapd_wake: %w", err)
	}
	c.links = append(c.links, kw)
	oom, err := link.AttachTracing(link.TracingOptions{Program: c.objs.HandleMarkVictim})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach tp_btf/mark_victim (kernel 6.6+BTF required): %w", err)
	}
	c.links = append(c.links, oom)
	return c, nil
}

func (c *MemCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

func (c *MemCollector) Poll(interval time.Duration) (MemSnapshot, error) {
	elapsed := c.measuredElapsed(interval)
	window := NewObservationWindow(time.Now(), elapsed)
	if !window.Valid() {
		return MemSnapshot{}, fmt.Errorf("invalid memory observation window: %s", elapsed)
	}
	if err := c.refreshTargetTGIDs(); err != nil {
		return MemSnapshot{}, err
	}
	total, avail, err := readMemInfo()
	if err != nil {
		return MemSnapshot{}, err
	}
	psi, err := readMemoryPSI()
	if err != nil {
		return MemSnapshot{}, err
	}
	vm, err := readVMStat()
	if err != nil {
		return MemSnapshot{}, err
	}

	snap := MemSnapshot{
		Window:         window,
		MemTotalKB:     total,
		MemAvailableKB: avail,
		Targeted:       c.target.enabled(),
	}
	if total > 0 {
		snap.MemAvailablePct = float64(avail) / float64(total) * 100
	}
	if c.psiPrimed && elapsed > 0 {
		secondsUS := float64(elapsed) / float64(time.Microsecond)
		snap.PSISomePct = float64(saturatingSub(psi.someUS, c.prevPSI.someUS)) / secondsUS * 100
		snap.PSIFullPct = float64(saturatingSub(psi.fullUS, c.prevPSI.fullUS)) / secondsUS * 100
	}
	c.prevPSI, c.psiPrimed = psi, true
	if c.vmPrimed {
		snap.PgscanDirect = saturatingSub(vm.PgscanDirect, c.prevVM.PgscanDirect)
		snap.PgscanKswapd = saturatingSub(vm.PgscanKswapd, c.prevVM.PgscanKswapd)
		snap.Pgsteal = saturatingSub(vm.Pgsteal, c.prevVM.Pgsteal)
		snap.Pgmajfault = saturatingSub(vm.Pgmajfault, c.prevVM.Pgmajfault)
		snap.VMStatOOMKills = saturatingSub(vm.OOMKill, c.prevVM.OOMKill)
	}
	c.prevVM, c.vmPrimed = vm, true

	var kw uint64
	if err := c.objs.KswapdWakes.Lookup(uint32(0), &kw); err != nil {
		return snap, fmt.Errorf("read kswapd_wakes: %w", err)
	}
	snap.KswapdWakes = saturatingSub(kw, c.prevKswapd)
	c.prevKswapd = kw

	seconds := elapsed.Seconds()
	procAll := make(map[uint32]MemProc)
	rssNow := make(map[uint32]MemProc)
	nextFault := make(map[uint32]fault)

	cur := make(map[uint32]memStat)
	var pid uint32
	var raw memStat
	it := c.objs.MemStats.Iterate()
	for it.Next(&pid, &raw) {
		cur[pid] = raw
	}
	if err := it.Err(); err != nil {
		return snap, fmt.Errorf("iterate mem_stats: %w", err)
	}
	var globalReclaimNS uint64
	for pid, value := range cur {
		old := c.prev[pid]
		dCount := saturatingSub(value.DirectReclaimCount, old.DirectReclaimCount)
		dNS := saturatingSub(value.DirectReclaimNs, old.DirectReclaimNs)
		globalReclaimNS += dNS
		proc := procAll[pid]
		proc.Pid = pid
		proc.DirectReclaimCount = dCount
		proc.DirectReclaimMs = float64(dNS) / 1e6
		if proc.Comm == "" {
			proc.Comm = commToString(value.Comm)
		}
		procAll[pid] = proc
		if shouldDeleteStale(c.stale, pid, dCount == 0 && dNS == 0) {
			_ = c.objs.MemStats.Delete(pid)
			delete(cur, pid)
		}
	}
	if seconds > 0 {
		snap.DirectReclaimMsPerSec = float64(globalReclaimNS) / 1e6 / seconds
	}

	curOOM := make(map[uint32]oomStat)
	var oomRaw oomStat
	oomIt := c.objs.OomStats.Iterate()
	for oomIt.Next(&pid, &oomRaw) {
		curOOM[pid] = oomRaw
	}
	if err := oomIt.Err(); err != nil {
		return snap, fmt.Errorf("iterate oom_stats: %w", err)
	}
	if err := drainObservedTGIDs(c.objs.ObservedTgids, c.target); err != nil {
		return snap, err
	}
	for pid, value := range curOOM {
		dCount := saturatingSub(value.Count, c.prevOOM[pid].Count)
		if dCount > 0 {
			snap.OOMVictimCount += dCount
			victim := procAll[pid]
			victim.Pid = pid
			victim.OOMVictimCount = dCount
			if victim.Comm == "" {
				victim.Comm = commToString(value.Comm)
			}
			if !c.target.enabled() || value.InTarget != 0 {
				snap.OOMVictims = append(snap.OOMVictims, victim)
				procAll[pid] = victim
			}
		}
		if shouldDeleteStale(c.oomStale, pid, dCount == 0) {
			_ = c.objs.OomStats.Delete(pid)
			delete(curOOM, pid)
		}
	}

	// /proc-wide RSS/fault attribution is O(number of processes). Run it only
	// once system evidence can actually satisfy the detector's pressure side;
	// BPF reclaim and OOM evidence above remain available on every window.
	needProcAttribution := snap.MemAvailablePct < c.scanFloor ||
		snap.PSISomePct >= MemPSISomeSignalPct ||
		snap.PSIFullPct >= MemPSIFullSignalPct ||
		snap.DirectReclaimMsPerSec >= MemDirectReclaimSignalMsPerSec ||
		snap.OOMVictimCount > 0
	if needProcAttribution {
		rssNow = readProcRSSSnapshot()
		nextFault = make(map[uint32]fault, len(rssNow))
		for pid, rssProc := range rssNow {
			maj, min := readProcFaults(pid)
			nextFault[pid] = fault{maj: maj, min: min}
			proc := procAll[pid]
			proc.Pid = pid
			proc.Comm = rssProc.Comm
			proc.RSSKB = rssProc.RSSKB
			proc.AnonRSSKB = rssProc.AnonRSSKB
			if c.procPrimed {
				oldRSS := c.prevRSS[pid]
				proc.RSSDeltaKB = saturatingSub(proc.RSSKB, oldRSS.rss)
				proc.AnonRSSDeltaKB = saturatingSub(proc.AnonRSSKB, oldRSS.anon)
				oldFault := c.prevFault[pid]
				proc.MajFlt = saturatingSub(maj, oldFault.maj)
				proc.MinFlt = saturatingSub(min, oldFault.min)
				if seconds > 0 {
					proc.MajFltPerSec = float64(proc.MajFlt) / seconds
					proc.AnonRSSGrowthKBPerSec = float64(proc.AnonRSSDeltaKB) / seconds
				}
			}
			procAll[pid] = proc
		}
	}

	for _, proc := range procAll {
		if hasMemContribution(proc) {
			snap.GlobalContribution = true
		}
		if c.target.enabled() && !c.target.containsTGID(proc.Pid) {
			continue
		}
		if hasCollectedMemProcSignal(proc) {
			snap.Procs = append(snap.Procs, proc)
		}
	}
	scopeRSS := rssNow
	if c.target.enabled() {
		scopeRSS = make(map[uint32]MemProc)
		for pid, proc := range procAll {
			if c.target.containsTGID(pid) {
				scopeRSS[pid] = proc
			}
		}
	}
	snap.TopRSSProc = topRSSProc(scopeRSS)
	sort.Slice(snap.Procs, func(i, j int) bool { return snap.Procs[i].Pid < snap.Procs[j].Pid })
	sort.Slice(snap.OOMVictims, func(i, j int) bool { return snap.OOMVictims[i].Pid < snap.OOMVictims[j].Pid })

	c.prev = cur
	c.prevOOM = curOOM
	if needProcAttribution {
		c.prevRSS = snapshotRSS(rssNow)
		c.prevFault = nextFault
		c.procPrimed = true
	} else {
		c.prevRSS = make(map[uint32]rssSample)
		c.prevFault = make(map[uint32]fault)
		c.procPrimed = false
	}
	return snap, nil
}

func (c *MemCollector) measuredElapsed(fallback time.Duration) time.Duration {
	now := monotonicNowNS()
	old := c.lastPollNS
	c.lastPollNS = now
	if old != 0 && now > old {
		return time.Duration(now - old)
	}
	return fallback
}

func (c *MemCollector) refreshTargetTGIDs() error {
	if !c.target.enabled() {
		return nil
	}
	c.target.refresh()
	if err := drainObservedTGIDs(c.objs.ObservedTgids, c.target); err != nil {
		return err
	}
	if err := c.objs.TargetPid.Put(uint32(0), c.target.bpfFilterRoot()); err != nil {
		return fmt.Errorf("update target root identity: %w", err)
	}
	return syncTargetTGIDMap(c.objs.TargetTgids, c.target.targetTGIDSeeds())
}

func hasCollectedMemProcSignal(proc MemProc) bool {
	return proc.DirectReclaimCount > 0 || proc.MajFlt > 0 ||
		proc.AnonRSSGrowthKBPerSec >= MemAnonRSSGrowthSignalKBPerSec || proc.OOMVictimCount > 0
}

func hasMemContribution(proc MemProc) bool {
	return proc.DirectReclaimCount > 0 || proc.DirectReclaimMs > 0 ||
		proc.AnonRSSGrowthKBPerSec >= MemAnonRSSGrowthSignalKBPerSec ||
		proc.MajFltPerSec >= MemMajorFaultSignalPerSec
}

func readProcRSSSnapshot() map[uint32]MemProc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make(map[uint32]MemProc)
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		rss, anon := readProcRSS(pid)
		out[pid] = MemProc{Pid: pid, Comm: readProcName(pid), RSSKB: rss, AnonRSSKB: anon}
	}
	return out
}

func topRSSProc(procs map[uint32]MemProc) MemProc {
	var best MemProc
	for _, proc := range procs {
		if proc.RSSKB > best.RSSKB {
			best = proc
		}
	}
	return best
}

func snapshotRSS(procs map[uint32]MemProc) map[uint32]rssSample {
	next := make(map[uint32]rssSample, len(procs))
	for pid, proc := range procs {
		next[pid] = rssSample{rss: proc.RSSKB, anon: proc.AnonRSSKB}
	}
	return next
}

func readProcRSS(pid uint32) (rssKB, anonRSSKB uint64) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "VmRSS:":
			rssKB = value
		case "RssAnon:":
			anonRSSKB = value
		}
	}
	return rssKB, anonRSSKB
}

func readProcName(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saturatingSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func readMemInfo() (total, avail uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			avail = value
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	if total == 0 {
		return 0, 0, fmt.Errorf("/proc/meminfo has no MemTotal")
	}
	return total, avail, nil
}

func readMemoryPSI() (psiSample, error) {
	f, err := os.Open("/proc/pressure/memory")
	if err != nil {
		return psiSample{}, fmt.Errorf("open memory PSI (kernel PSI required): %w", err)
	}
	defer f.Close()
	var out psiSample
	found := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		var total uint64
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "total=") {
				total, _ = strconv.ParseUint(strings.TrimPrefix(field, "total="), 10, 64)
				break
			}
		}
		switch fields[0] {
		case "some":
			out.someUS, found = total, found|1
		case "full":
			out.fullUS, found = total, found|2
		}
	}
	if err := sc.Err(); err != nil {
		return psiSample{}, fmt.Errorf("read memory PSI: %w", err)
	}
	if found != 3 {
		return psiSample{}, fmt.Errorf("memory PSI is missing some/full totals")
	}
	return out, nil
}

func readVMStat() (vmStatSample, error) {
	f, err := os.Open("/proc/vmstat")
	if err != nil {
		return vmStatSample{}, fmt.Errorf("open /proc/vmstat: %w", err)
	}
	defer f.Close()
	var out vmStatSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch fields[0] {
		case "pgscan_direct":
			out.PgscanDirect += value
		case "pgscan_kswapd":
			out.PgscanKswapd += value
		// Use the source dimension only. Summing pgsteal_{direct,kswapd}
		// together with pgsteal_{anon,file} would double-count the same pages.
		case "pgsteal_direct", "pgsteal_kswapd":
			out.Pgsteal += value
		case "pgmajfault":
			out.Pgmajfault = value
		case "oom_kill":
			out.OOMKill = value
		}
	}
	if err := sc.Err(); err != nil {
		return vmStatSample{}, fmt.Errorf("read /proc/vmstat: %w", err)
	}
	return out, nil
}

func readProcFaults(pid uint32) (maj, min uint64) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0
	}
	s := string(b)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+2 >= len(s) {
		return 0, 0
	}
	fields := strings.Fields(s[rp+2:])
	if len(fields) > 9 {
		min, _ = strconv.ParseUint(fields[7], 10, 64)
		maj, _ = strconv.ParseUint(fields[9], 10, 64)
	}
	return maj, min
}
