package collector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const ioNSlots = 40

// ioStat matches struct dev_stat in block.bpf.c. Lock is opaque in user space.
type ioStat struct {
	Lock        uint32
	Pad         uint32
	Count       uint64
	TotalLatNs  uint64
	Bytes       uint64
	QueueAreaNs uint64
	QueueLastNs uint64
	Inflight    int64
	Slots       [ioNSlots]uint64
}

type ioHealthStat struct {
	DuplicateIssue    uint64
	CompletionMiss    uint64
	MapUpdateFail     uint64
	PartialCompletion uint64
	IOError           uint64
}

// IOSample contains completed-request latency and a time-weighted queue depth.
type IOSample struct {
	Dev               uint32
	DevName           string
	IOPS              float64
	AvgLatMs          float64
	P99LatMs          float64
	MaxLatMs          float64
	ThroughputMBps    float64
	QueueDepth        int64   // gauge at poll time
	AverageQueueDepth float64 // integral(queue depth)/actual elapsed time
	Window            ObservationWindow
}

type IOCollector struct {
	objs                       blockObjects
	links                      []link.Link
	prev                       map[uint32]ioStat
	devName                    map[uint32]string
	lastPoll                   time.Time
	lastInflight               uint64
	lastAverageQueueDepthMilli uint64
	statsFD                    io.Closer
	statsReady                 bool
}

func NewIOCollector() (*IOCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &IOCollector{
		prev:    make(map[uint32]ioStat),
		devName: loadPartitions(),
	}
	if statsFD, err := ebpf.EnableStats(0); err == nil {
		c.statsFD = statsFD
		c.statsReady = true
	}
	if err := loadBlockObjects(&c.objs, nil); err != nil {
		if c.statsFD != nil {
			_ = c.statsFD.Close()
		}
		return nil, fmt.Errorf("load typed block BPF objects (requires kernel 6.6+BTF): %w", err)
	}
	programs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"tp_btf/block_rq_complete", c.objs.HandleComplete},
		{"tp_btf/block_rq_issue", c.objs.HandleIssue},
	}
	for _, item := range programs {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: item.prog})
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("attach %s (requires typed tracepoints): %w", item.name, err)
		}
		c.links = append(c.links, lnk)
	}
	boundaryNS := monotonicNowNS()
	if boundaryNS == 0 {
		c.Close()
		return nil, fmt.Errorf("read monotonic I/O startup boundary")
	}
	if err := c.objs.StartupBoundaryNs.Put(uint32(0), boundaryNS); err != nil {
		c.Close()
		return nil, fmt.Errorf("arm I/O collection after both hooks attached: %w", err)
	}
	return c, nil
}

func (c *IOCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
	if c.statsFD != nil {
		_ = c.statsFD.Close()
		c.statsFD = nil
	}
}

// Poll derives deltas over the actual elapsed window. queue_area is extended
// to the poll boundary with the current inflight gauge, so a stable non-zero
// queue is represented even when no issue/complete event occurs near the tick.
func (c *IOCollector) Poll(interval time.Duration) ([]IOSample, error) {
	end := time.Now()
	start := c.lastPoll
	if start.IsZero() {
		start = end.Add(-interval)
	}
	elapsed := end.Sub(start)
	if elapsed <= 0 {
		return nil, fmt.Errorf("invalid I/O observation window: %s", elapsed)
	}
	pollMono := monotonicNowNS()

	cur := make(map[uint32]ioStat)
	var key, next uint32
	var val ioStat
	var cursor interface{}
	for {
		if err := c.objs.DevStats.NextKey(cursor, &next); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("iterate dev_stats keys: %w", err)
		}
		key = next
		cursor = &key
		if err := c.objs.DevStats.LookupWithFlags(&key, &val, ebpf.LookupLock); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return nil, fmt.Errorf("locked lookup dev_stats[%d]: %w", key, err)
		}
		if pollMono > val.QueueLastNs && val.Inflight > 0 {
			val.QueueAreaNs += (pollMono - val.QueueLastNs) * uint64(val.Inflight)
		}
		// This is a user-space snapshot boundary, not written back to the map.
		val.QueueLastNs = pollMono
		cur[key] = val
	}

	secs := elapsed.Seconds()
	elapsedNs := float64(elapsed.Nanoseconds())
	samples := make([]IOSample, 0, len(cur))
	var totalInflight uint64
	var totalQueueArea uint64
	for dev, v := range cur {
		p := c.prev[dev]
		dCount := counterDelta(v.Count, p.Count)
		dLat := counterDelta(v.TotalLatNs, p.TotalLatNs)
		dBytes := counterDelta(v.Bytes, p.Bytes)
		dQueueArea := counterDelta(v.QueueAreaNs, p.QueueAreaNs)
		if v.Inflight > 0 {
			totalInflight += uint64(v.Inflight)
		}
		totalQueueArea += dQueueArea
		if dCount == 0 {
			continue
		}
		s := IOSample{
			Dev:               dev,
			DevName:           c.devString(dev),
			IOPS:              float64(dCount) / secs,
			AvgLatMs:          float64(dLat) / float64(dCount) / 1e6,
			P99LatMs:          p99FromSlots(v.Slots, p.Slots, dCount),
			MaxLatMs:          float64(maxNSFromIOSlots(v.Slots, p.Slots)) / 1e6,
			ThroughputMBps:    float64(dBytes) / secs / 1e6,
			QueueDepth:        maxInt64(v.Inflight, 0),
			AverageQueueDepth: float64(dQueueArea) / elapsedNs,
			Window:            ObservationWindowBetween(start, end),
		}
		samples = append(samples, s)
	}
	c.prev = cur
	c.lastPoll = end
	c.lastInflight = totalInflight
	c.lastAverageQueueDepthMilli = uint64(float64(totalQueueArea) / elapsedNs * 1000)
	return samples, nil
}

// p99FromSlots uses the bucket upper bound. Bucket i contains latencies with
// floor(log2(ns)) == i, hence 2^(i+1)-1 is the conservative upper bound.
func p99FromSlots(cur, prev [ioNSlots]uint64, total uint64) float64 {
	if total == 0 {
		return 0
	}
	target := (total*99 + 99) / 100
	var cumulative uint64
	for slot := 0; slot < ioNSlots; slot++ {
		cumulative += counterDelta(cur[slot], prev[slot])
		if cumulative >= target {
			return float64(ioBucketUpperNS(slot)) / 1e6
		}
	}
	return float64(ioBucketUpperNS(ioNSlots-1)) / 1e6
}

func maxNSFromIOSlots(cur, prev [ioNSlots]uint64) uint64 {
	for slot := ioNSlots - 1; slot >= 0; slot-- {
		if counterDelta(cur[slot], prev[slot]) > 0 {
			return ioBucketUpperNS(slot)
		}
	}
	return 0
}

func ioBucketUpperNS(slot int) uint64 {
	return (uint64(1) << uint(slot+1)) - 1
}

func (c *IOCollector) devString(dev uint32) string {
	maj, min := dev>>20, dev&0xfffff
	if name, ok := c.devName[dev]; ok {
		return fmt.Sprintf("%d:%d %s", maj, min, name)
	}
	return fmt.Sprintf("%d:%d", maj, min)
}

func loadPartitions() map[uint32]string {
	m := make(map[uint32]string)
	f, err := os.Open("/proc/partitions")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var maj, min uint32
		var blocks uint64
		var name string
		if n, _ := fmt.Sscanf(sc.Text(), "%d %d %d %s", &maj, &min, &blocks, &name); n == 4 {
			m[(maj<<20)|(min&0xfffff)] = name
		}
	}
	return m
}
