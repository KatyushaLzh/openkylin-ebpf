package collector

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	histNSlots               = 32
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
