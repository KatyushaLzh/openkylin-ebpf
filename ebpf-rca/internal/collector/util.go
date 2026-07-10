package collector

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func readOnlineCPUs() ([]int, error) {
	raw, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, fmt.Errorf("read online CPU list: %w", err)
	}
	return parseCPUList(string(raw))
}

func parseCPUList(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("online CPU list is empty")
	}
	seen := make(map[int]struct{})
	for _, item := range strings.Split(raw, ",") {
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 || bounds[0] == "" {
			return nil, fmt.Errorf("invalid CPU range %q", item)
		}
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 0 {
			return nil, fmt.Errorf("invalid CPU id %q", bounds[0])
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid CPU range %q", item)
			}
		}
		if last > 1_000_000 {
			return nil, fmt.Errorf("CPU id %d is unreasonably large", last)
		}
		for cpu := first; cpu <= last; cpu++ {
			seen[cpu] = struct{}{}
		}
	}
	cpus := make([]int, 0, len(seen))
	for cpu := range seen {
		cpus = append(cpus, cpu)
	}
	sort.Ints(cpus)
	return cpus, nil
}

const (
	histNSlots               = 48
	staleWindowsBeforeDelete = 3
)

func monotonicNowNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func procExists(pid uint32) bool {
	if pid == 0 {
		return false
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil || !os.IsNotExist(err)
}

func shouldDeleteStale(stale map[uint32]int, pid uint32, inactive bool) bool {
	if inactive && !procExists(pid) {
		stale[pid]++
		return stale[pid] >= staleWindowsBeforeDelete
	}
	delete(stale, pid)
	return false
}

func maxNSFromSlots(cur, prev [histNSlots]uint64) uint64 {
	for slot := histNSlots - 1; slot >= 0; slot-- {
		if cur[slot] > prev[slot] {
			return uint64(1) << uint(slot)
		}
	}
	return 0
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
