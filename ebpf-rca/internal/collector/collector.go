package collector

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	cpuMaxStackDepth      = 32
	cpuSeedFrequencyHertz = 10
)

type taskKey struct {
	Tgid uint32
	Tid  uint32
}

// taskStat matches struct task_stat in cpu.bpf.c.
type taskStat struct {
	RunNs     uint64
	RunqNs    uint64
	RunqCount uint64
	Ctx       uint64
	Comm      [16]byte
}

type oncpuInfo struct {
	Task    taskKey
	StartNs uint64
}

type cpuStackKeyLocal struct {
	Tgid    uint32
	Tid     uint32
	StackID int32
	Pad     uint32
}

type cpuStackStatLocal struct {
	Count uint64
	RunNs uint64
}

// liveRunCredit tracks runtime already reported from a still-running interval.
// The kernel cumulative counter receives that interval only at sched_switch;
// outstandingNS is therefore repaid from a later kernel delta to avoid double
// counting across the two-map snapshot boundary.
type liveRunCredit struct {
	startNS       uint64
	reportedAtNS  uint64
	outstandingNS uint64
}

// Sample is one process-wide CPU sample. CPUUtil is the hottest single TID;
// ProcessCPUCores is the sum over all TIDs (and can legitimately exceed 1).
type Sample struct {
	Pid             uint32 // TGID: process identity
	Tid             uint32 // hottest TID in this window
	Comm            string
	CPUUtil         float64
	ProcessCPUCores float64
	CtxPerMin       float64
	RunqWaitUs      float64
	RunqCount       uint64
	HotStack        []string
	HotStackID      int32
	HotStackValid   bool
	HotStackSamples uint64
	Window          ObservationWindow
}

// CPUCollector loads typed scheduler tracepoints and reads window deltas.
type CPUCollector struct {
	objs       cpuObjects
	links      []link.Link
	prev       map[taskKey]taskStat
	prevStacks map[cpuStackKeyLocal]cpuStackStatLocal
	liveRuns   map[taskKey]liveRunCredit
	stale      map[taskKey]int
	lastPoll   time.Time
	statsFD    io.Closer
	statsReady bool
	perfFDs    []int
	selfTGID   uint32
}

func NewCPUCollector() (*CPUCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &CPUCollector{
		prev:       make(map[taskKey]taskStat),
		prevStacks: make(map[cpuStackKeyLocal]cpuStackStatLocal),
		liveRuns:   make(map[taskKey]liveRunCredit),
		stale:      make(map[taskKey]int),
		selfTGID:   uint32(os.Getpid()),
	}
	// Keep the stats-enable FD open for the collector lifetime. Failure is not
	// fatal to collection, but is surfaced in the health counters.
	if statsFD, err := ebpf.EnableStats(0); err == nil {
		c.statsFD = statsFD
		c.statsReady = true
	}
	if err := loadCpuObjects(&c.objs, nil); err != nil {
		if c.statsFD != nil {
			_ = c.statsFD.Close()
		}
		return nil, fmt.Errorf("load typed sched BPF objects (requires kernel 6.6+BTF): %w", err)
	}
	programs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"tp_btf/sched_switch", c.objs.HandleSwitch},
		{"tp_btf/sched_wakeup", c.objs.HandleWakeup},
		{"tp_btf/sched_wakeup_new", c.objs.HandleWakeupNew},
	}
	for _, item := range programs {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: item.prog})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s (requires typed tracepoints): %w", item.name, err)
		}
		c.links = append(c.links, lnk)
	}
	perfFDs, err := attachCPUSeedEvents(c.objs.HandleSeedOncpu)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach per-CPU running-task heartbeat: %w", err)
	}
	c.perfFDs = perfFDs
	return c, nil
}

func (c *CPUCollector) Close() {
	for _, fd := range c.perfFDs {
		_ = unix.Close(fd)
	}
	c.perfFDs = nil
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
	if c.statsFD != nil {
		_ = c.statsFD.Close()
		c.statsFD = nil
	}
}

func attachCPUSeedEvents(prog *ebpf.Program) ([]int, error) {
	if prog == nil {
		return nil, fmt.Errorf("heartbeat BPF program is unavailable")
	}
	cpus, err := readOnlineCPUs()
	if err != nil {
		return nil, err
	}
	fds := make([]int, 0, len(cpus))
	closeAll := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	for _, cpu := range cpus {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample: cpuSeedFrequencyHertz,
			Bits:   unix.PerfBitDisabled | unix.PerfBitFreq,
		}
		attr.Size = uint32(unsafe.Sizeof(attr))
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("open CPU-clock event on cpu %d: %w", cpu, err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
			_ = unix.Close(fd)
			closeAll()
			return nil, fmt.Errorf("bind heartbeat on cpu %d: %w", cpu, err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			_ = unix.Close(fd)
			closeAll()
			return nil, fmt.Errorf("enable heartbeat on cpu %d: %w", cpu, err)
		}
		fds = append(fds, fd)
	}
	if len(fds) == 0 {
		return nil, fmt.Errorf("no online CPUs")
	}
	return fds, nil
}

type cpuThreadDelta struct {
	key       taskKey
	comm      string
	runNs     uint64
	runqNs    uint64
	runqCount uint64
	ctx       uint64
}

type cpuProcessDelta struct {
	tgid      uint32
	runNs     uint64
	runqNs    uint64
	runqCount uint64
	ctx       uint64
	top       cpuThreadDelta
	hasTop    bool
}

type stackChoice struct {
	id    int32
	count uint64
	runNs uint64
}

// Poll uses the actual time since the prior poll. interval is only the first
// poll fallback; this avoids attributing delayed ticks to a nominal 1 second.
func (c *CPUCollector) Poll(interval time.Duration) ([]Sample, error) {
	end := time.Now()
	start := c.lastPoll
	if start.IsZero() {
		start = end.Add(-interval)
	}
	elapsed := end.Sub(start)
	if elapsed <= 0 {
		return nil, fmt.Errorf("invalid CPU observation window: %s", elapsed)
	}

	raw := make(map[taskKey]taskStat)
	var key taskKey
	var val taskStat
	it := c.objs.Stats.Iterate()
	for it.Next(&key, &val) {
		raw[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate CPU stats: %w", err)
	}

	// Snapshot live intervals after cumulative stats. A switch between these
	// reads can defer completed runtime to the next poll, but liveRunDelta keeps
	// synthetic runtime as debt and prevents either a lifetime-sized wrap or a
	// later double count.
	nowNS := monotonicNowNS()
	runningByTask := make(map[taskKey]oncpuInfo)
	var tid uint32
	var running oncpuInfo
	it = c.objs.OncpuStart.Iterate()
	for it.Next(&tid, &running) {
		runningByTask[running.Task] = running
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate CPU oncpu_start: %w", err)
	}

	stackCur := make(map[cpuStackKeyLocal]cpuStackStatLocal)
	var stackKey cpuStackKeyLocal
	var stackVal cpuStackStatLocal
	it = c.objs.StackStats.Iterate()
	for it.Next(&stackKey, &stackVal) {
		stackCur[stackKey] = stackVal
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate CPU stack_stats: %w", err)
	}
	stackTop := make(map[taskKey]stackChoice)
	for sk, v := range stackCur {
		p := c.prevStacks[sk]
		dCount := counterDelta(v.Count, p.Count)
		dRun := counterDelta(v.RunNs, p.RunNs)
		if dCount == 0 {
			continue
		}
		tk := taskKey{Tgid: sk.Tgid, Tid: sk.Tid}
		if old, ok := stackTop[tk]; !ok || dRun > old.runNs {
			stackTop[tk] = stackChoice{id: sk.StackID, count: dCount, runNs: dRun}
		}
	}

	processes := make(map[uint32]*cpuProcessDelta)
	for tk, v := range raw {
		if tk.Tgid == c.selfTGID {
			_ = c.objs.Stats.Delete(tk)
			_ = c.objs.OncpuStart.Delete(tk.Tid)
			_ = c.objs.EnqueueTs.Delete(tk.Tid)
			delete(raw, tk)
			delete(c.liveRuns, tk)
			delete(c.stale, tk)
			for sk := range stackCur {
				if sk.Tgid == tk.Tgid && sk.Tid == tk.Tid {
					_ = c.objs.StackStats.Delete(sk)
					delete(stackCur, sk)
				}
			}
			continue
		}
		p := c.prev[tk]
		running, isRunning := runningByTask[tk]
		d := cpuThreadDelta{
			key:       tk,
			comm:      commToString(v.Comm),
			runNs:     c.liveRunDelta(tk, v.RunNs, p.RunNs, running, isRunning, nowNS),
			runqNs:    counterDelta(v.RunqNs, p.RunqNs),
			runqCount: counterDelta(v.RunqCount, p.RunqCount),
			ctx:       counterDelta(v.Ctx, p.Ctx),
		}
		inactive := d.runNs == 0 && d.ctx == 0 && d.runqCount == 0
		if c.shouldDeleteTask(tk, inactive) {
			_ = c.objs.Stats.Delete(tk)
			_ = c.objs.OncpuStart.Delete(tk.Tid)
			_ = c.objs.EnqueueTs.Delete(tk.Tid)
			delete(raw, tk)
			delete(c.liveRuns, tk)
			for sk := range stackCur {
				if sk.Tgid == tk.Tgid && sk.Tid == tk.Tid {
					_ = c.objs.StackStats.Delete(sk)
					delete(stackCur, sk)
				}
			}
			continue
		}
		if inactive {
			continue
		}
		proc := processes[tk.Tgid]
		if proc == nil {
			proc = &cpuProcessDelta{tgid: tk.Tgid}
			processes[tk.Tgid] = proc
		}
		proc.runNs += d.runNs
		proc.runqNs += d.runqNs
		proc.runqCount += d.runqCount
		proc.ctx += d.ctx
		if !proc.hasTop || d.runNs > proc.top.runNs {
			proc.top = d
			proc.hasTop = true
		}
	}

	elapsedNs := float64(elapsed.Nanoseconds())
	elapsedMin := elapsed.Minutes()
	samples := make([]Sample, 0, len(processes))
	for _, proc := range processes {
		s := Sample{
			Pid:             proc.tgid,
			Tid:             proc.top.key.Tid,
			Comm:            proc.top.comm,
			CPUUtil:         float64(proc.top.runNs) / elapsedNs,
			ProcessCPUCores: float64(proc.runNs) / elapsedNs,
			RunqCount:       proc.runqCount,
			Window:          ObservationWindowBetween(start, end),
		}
		if elapsedMin > 0 {
			s.CtxPerMin = float64(proc.ctx) / elapsedMin
		}
		if proc.runqCount > 0 {
			s.RunqWaitUs = float64(proc.runqNs) / float64(proc.runqCount) / 1000
		}
		if choice, ok := stackTop[proc.top.key]; ok {
			s.HotStackSamples = choice.count
			s.HotStackID = choice.id
			s.HotStackValid = true
		}
		samples = append(samples, s)
	}
	c.prev = raw
	c.prevStacks = stackCur
	c.lastPoll = end
	return samples, nil
}

func (c *CPUCollector) liveRunDelta(key taskKey, current, previous uint64,
	running oncpuInfo, isRunning bool, nowNS uint64) uint64 {
	credit := c.liveRuns[key]
	if current < previous {
		// Counter replacement/PID reuse starts a new accounting generation.
		credit = liveRunCredit{}
	}
	delta := counterDelta(current, previous)
	if credit.outstandingNS > 0 {
		repaid := credit.outstandingNS
		if repaid > delta {
			repaid = delta
		}
		delta -= repaid
		credit.outstandingNS -= repaid
	}

	var synthetic uint64
	if isRunning && nowNS > running.StartNs {
		total := nowNS - running.StartNs
		if credit.startNS == running.StartNs && total >= credit.reportedAtNS {
			synthetic = total - credit.reportedAtNS
		} else {
			// A different start timestamp means one or more intervals completed
			// between map reads. Their prior credit remains outstanding.
			synthetic = total
		}
		credit.startNS = running.StartNs
		credit.reportedAtNS = total
		credit.outstandingNS += synthetic
	} else {
		credit.startNS = 0
		credit.reportedAtNS = 0
	}

	if credit.outstandingNS == 0 && credit.startNS == 0 {
		delete(c.liveRuns, key)
	} else {
		c.liveRuns[key] = credit
	}
	return delta + synthetic
}

func (c *CPUCollector) shouldDeleteTask(key taskKey, inactive bool) bool {
	if inactive && !taskExists(key) {
		c.stale[key]++
		return c.stale[key] >= staleWindowsBeforeDelete
	}
	delete(c.stale, key)
	return false
}

func taskExists(key taskKey) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", key.Tgid, key.Tid))
	return err == nil || !os.IsNotExist(err)
}

func counterDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	// Map entry replacement/PID reuse: treat the current value as a new base.
	return cur
}

func commToString(b [16]byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

type procMapping struct {
	start, end uint64
	fileOffset uint64
	module     string
}

func readProcMappings(tgid uint32) []procMapping {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", tgid))
	if err != nil {
		return nil
	}
	defer f.Close()

	var mappings []procMapping
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		rangeParts := strings.SplitN(fields[0], "-", 2)
		if len(rangeParts) != 2 {
			continue
		}
		start, e1 := strconv.ParseUint(rangeParts[0], 16, 64)
		end, e2 := strconv.ParseUint(rangeParts[1], 16, 64)
		offset, e3 := strconv.ParseUint(fields[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		module := "anonymous"
		if len(fields) >= 6 {
			module = strings.Join(fields[5:], " ")
			if !strings.HasPrefix(module, "[") {
				module = filepath.Base(module)
			}
		}
		mappings = append(mappings, procMapping{start, end, offset, module})
	}
	return mappings
}

func moduleOffset(addr uint64, mappings []procMapping) string {
	for _, m := range mappings {
		if addr >= m.start && addr < m.end {
			return fmt.Sprintf("%s+0x%x", m.module, addr-m.start+m.fileOffset)
		}
	}
	return fmt.Sprintf("unknown+0x%x", addr)
}

// ResolveUserStack performs the comparatively expensive /proc/<tgid>/maps
// symbolization only after the detector has confirmed an anomaly.
func (c *CPUCollector) ResolveUserStack(tgid uint32, id int32, max int) []string {
	if id < 0 || max <= 0 {
		return nil
	}
	var frames [cpuMaxStackDepth]uint64
	if err := c.objs.UserStacks.Lookup(uint32(id), &frames); err != nil {
		return nil
	}
	mappings := readProcMappings(tgid)
	out := make([]string, 0, max)
	for _, addr := range frames {
		if addr == 0 || len(out) >= max {
			break
		}
		out = append(out, moduleOffset(addr, mappings))
	}
	return out
}
