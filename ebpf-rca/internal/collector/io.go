package collector

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const ioNSlots = 32

// ioStat 与 block.bpf.c 中的 struct dev_stat 二进制布局一致。
type ioStat struct {
	Count      uint64
	TotalLatNs uint64
	MaxLatNs   uint64
	Bytes      uint64
	Inflight   int64
	Slots      [ioNSlots]uint64
}

// IOSample 是单个块设备在一个窗口内的派生 I/O 指标。
type IOSample struct {
	Dev            uint32
	DevName        string  // "8:0 sda"
	IOPS           float64
	AvgLatMs       float64
	P99LatMs       float64
	MaxLatMs       float64
	ThroughputMBps float64
	QueueDepth     int64
}

// IOCollector 加载 I/O 场景的 eBPF 程序并按窗口读取块层时延数据。
type IOCollector struct {
	objs    blockObjects
	links   []link.Link
	prev    map[uint32]ioStat
	devName map[uint32]string
}

// NewIOCollector 加载字节码、挂载块层 tracepoint、载入设备名表。
func NewIOCollector() (*IOCollector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}
	c := &IOCollector{
		prev:    make(map[uint32]ioStat),
		devName: loadPartitions(),
	}
	if err := loadBlockObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}
	is, err := link.Tracepoint("block", "block_rq_issue", c.objs.HandleIssue, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach block_rq_issue: %w", err)
	}
	c.links = append(c.links, is)

	cp, err := link.Tracepoint("block", "block_rq_complete", c.objs.HandleComplete, nil)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach block_rq_complete: %w", err)
	}
	c.links = append(c.links, cp)
	return c, nil
}

// Close 卸载探针并释放资源。
func (c *IOCollector) Close() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.objs.Close()
}

// Poll 读取 dev_stats，计算自上次调用以来的差分与 P99。
func (c *IOCollector) Poll(interval time.Duration) ([]IOSample, error) {
	cur := make(map[uint32]ioStat)
	var key uint32
	var val ioStat
	it := c.objs.DevStats.Iterate()
	for it.Next(&key, &val) {
		cur[key] = val
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate dev_stats: %w", err)
	}

	secs := interval.Seconds()
	var samples []IOSample
	for dev, v := range cur {
		p := c.prev[dev]
		dCount := v.Count - p.Count
		dLat := v.TotalLatNs - p.TotalLatNs
		dBytes := v.Bytes - p.Bytes
		if dCount == 0 {
			continue
		}
		s := IOSample{
			Dev:            dev,
			DevName:        c.devString(dev),
			MaxLatMs:       float64(v.MaxLatNs) / 1e6,
			QueueDepth:     v.Inflight,
			ThroughputMBps: float64(dBytes) / secs / 1e6,
		}
		if secs > 0 {
			s.IOPS = float64(dCount) / secs
		}
		s.AvgLatMs = float64(dLat) / float64(dCount) / 1e6
		s.P99LatMs = p99FromSlots(v.Slots, p.Slots, dCount)
		samples = append(samples, s)
	}
	c.prev = cur
	return samples, nil
}

// p99FromSlots 由 log2(ns) 直方图差分估算 P99（取该槽位上界 2^slot ns）。
func p99FromSlots(cur, prev [ioNSlots]uint64, total uint64) float64 {
	if total == 0 {
		return 0
	}
	target := float64(total) * 0.99
	var cum float64
	for slot := 0; slot < ioNSlots; slot++ {
		cum += float64(cur[slot] - prev[slot])
		if cum >= target {
			return float64(uint64(1)<<uint(slot)) / 1e6 // ns -> ms
		}
	}
	return float64(uint64(1)<<uint(ioNSlots-1)) / 1e6
}

func (c *IOCollector) devString(dev uint32) string {
	maj, min := dev>>20, dev&0xfffff
	if name, ok := c.devName[dev]; ok {
		return fmt.Sprintf("%d:%d %s", maj, min, name)
	}
	return fmt.Sprintf("%d:%d", maj, min)
}

// loadPartitions 从 /proc/partitions 构建 dev_t -> 设备名 映射。
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
