package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type targetTracker struct {
	root  uint32
	tgids map[uint32]struct{}
	tids  map[uint32]struct{}
}

func newTargetTracker(root uint32) *targetTracker {
	return &targetTracker{root: root}
}

func (t *targetTracker) enabled() bool {
	return t != nil && t.root != 0
}

func (t *targetTracker) refresh() {
	if !t.enabled() {
		return
	}
	snap := readProcTreeSnapshot()
	if _, ok := snap[t.root]; !ok {
		return
	}
	tgids := collectTargetTGIDs(t.root, snap)
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
	t.tgids = tgids
	t.tids = tids
}

func (t *targetTracker) containsTGID(pid uint32) bool {
	if !t.enabled() {
		return true
	}
	if pid == 0 {
		return false
	}
	if len(t.tgids) == 0 {
		return pid == t.root
	}
	_, ok := t.tgids[pid]
	return ok
}

func (t *targetTracker) containsTID(tid uint32) bool {
	if !t.enabled() {
		return true
	}
	if tid == 0 {
		return false
	}
	if len(t.tids) == 0 {
		return tid == t.root
	}
	_, ok := t.tids[tid]
	return ok
}

func (t *targetTracker) targetTGIDs() []uint32 {
	if !t.enabled() {
		return nil
	}
	out := make([]uint32, 0, len(t.tgids)+1)
	if len(t.tgids) == 0 {
		return append(out, t.root)
	}
	for pid := range t.tgids {
		out = append(out, pid)
	}
	return out
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
