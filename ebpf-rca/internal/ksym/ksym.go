// Package ksym 提供内核符号解析：从 /proc/kallsyms 将地址映射为函数名，
// 用于把 off-CPU 阻塞栈符号化（如 futex_wait_queue / __mutex_lock_slowpath），
// 形成可读、可回溯的"线程堆栈聚集"证据。
package ksym

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Table 是按地址升序排列的内核符号表。
type Table struct {
	addrs []uint64
	names []string
}

// Load 读取 /proc/kallsyms（需 root，且 kptr_restrict 允许）。
func Load() (*Table, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	t := &Table{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		t.addrs = append(t.addrs, addr)
		t.names = append(t.names, fields[2])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(t.addrs) == 0 {
		return nil, fmt.Errorf("kallsyms 为空（可能 kptr_restrict 受限，请用 root 运行）")
	}

	idx := make([]int, len(t.addrs))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return t.addrs[idx[a]] < t.addrs[idx[b]] })
	sa := make([]uint64, len(t.addrs))
	sn := make([]string, len(t.names))
	for i, j := range idx {
		sa[i] = t.addrs[j]
		sn[i] = t.names[j]
	}
	t.addrs, t.names = sa, sn
	return t, nil
}

// Resolve 返回包含 addr 的最近符号名；找不到时返回十六进制地址。
func (t *Table) Resolve(addr uint64) string {
	if t == nil || len(t.addrs) == 0 {
		return fmt.Sprintf("0x%x", addr)
	}
	i := sort.Search(len(t.addrs), func(i int) bool { return t.addrs[i] > addr })
	if i == 0 {
		return fmt.Sprintf("0x%x", addr)
	}
	return t.names[i-1]
}
