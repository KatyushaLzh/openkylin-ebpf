// SPDX-License-Identifier: GPL-2.0
//
// Per-process syscall frequency and latency aggregation using typed BTF
// tracepoints.  The start map is LRU so a burst of short-lived threads cannot
// permanently exhaust it; eviction/missing exits are exposed as health data.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define NSLOTS 48
#define TARGET_PROC_START_SEED (1ULL << 63)
#define TARGET_PROC_START_MASK (TARGET_PROC_START_SEED - 1)
#define NS_PER_USER_TICK 10000000ULL

enum syscall_health_index {
	SYSCALL_HEALTH_START_UPDATE_FAIL,
	SYSCALL_HEALTH_EXIT_MISS,
	SYSCALL_HEALTH_STAT_UPDATE_FAIL,
	SYSCALL_HEALTH_TARGET_UPDATE_FAIL,
	SYSCALL_HEALTH_MAX,
};

struct sc_start {
	__u64 ts;
	__u32 nr;
	__u32 pad;
};

struct sc_key {
	__u32 pid; // TGID
	__u32 nr;
};

struct sc_stat {
	__u64 count;
	__u64 total_ns;
	__u64 max_ns;
	char comm[TASK_COMM_LEN];
	__u64 slots[NSLOTS];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct sc_start);
} start SEC(".maps");

// TIDs that were already alive before attachment may return from a syscall
// whose enter event was unobservable. User space seeds this set once so those
// first exits are separated from real post-attach LRU/data-loss misses.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} startup_tids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct sc_key);
	__type(value, struct sc_stat);
} syscall_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} target_tgids SEC(".maps");

// Kernel-discovered descendants are drained by user space every Poll. This
// closes the gap for children that fork and exit between /proc snapshots.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} observed_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SYSCALL_HEALTH_MAX);
	__type(key, __u32);
	__type(value, __u64);
} health SEC(".maps");

static __always_inline void health_inc(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&health, &index);
	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline bool target_identity_matches(__u64 stored, __u64 identity)
{
	if (!stored || !identity)
		return false;
	if (!(stored & TARGET_PROC_START_SEED))
		return stored == identity;
	__u64 expected = stored & TARGET_PROC_START_MASK;
	__u64 actual = identity / NS_PER_USER_TICK;
	return expected > actual ? expected - actual <= 1 : actual - expected <= 1;
}

static __always_inline bool allowed_tgid(__u32 tgid)
{
	__u32 key = 0;
	__u32 *target = bpf_map_lookup_elem(&target_pid, &key);
	if (!target || *target == 0)
		return true;

	struct task_struct *task = bpf_get_current_task_btf();
	__u64 identity = BPF_CORE_READ(task, group_leader, start_boottime);
	__u64 *admitted = bpf_map_lookup_elem(&target_tgids, &tgid);
	if (admitted && target_identity_matches(*admitted, identity)) {
		bool seeded = *admitted & TARGET_PROC_START_SEED;
		if (seeded && bpf_map_update_elem(&target_tgids, &tgid, &identity, BPF_ANY))
			health_inc(SYSCALL_HEALTH_TARGET_UPDATE_FAIL);
		__u64 *seen = bpf_map_lookup_elem(&observed_tgids, &tgid);
		if ((!seen || *seen != identity) &&
		    bpf_map_update_elem(&observed_tgids, &tgid, &identity, BPF_ANY))
			health_inc(SYSCALL_HEALTH_TARGET_UPDATE_FAIL);
		return true;
	}

#pragma unroll
	for (int i = 0; i < 16; i++) {
		if (!task)
			break;
		__u32 ancestor = BPF_CORE_READ(task, tgid);
		if (ancestor == *target) {
			long observed_rc = bpf_map_update_elem(&observed_tgids, &tgid, &identity, BPF_ANY);
			long target_rc = bpf_map_update_elem(&target_tgids, &tgid, &identity, BPF_ANY);
			if (observed_rc || target_rc)
				health_inc(SYSCALL_HEALTH_TARGET_UPDATE_FAIL);
			return true;
		}
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		if (!parent || parent == task)
			break;
		task = parent;
	}
	return false;
}

static __always_inline __u32 log2_u64(__u64 value)
{
	__u32 result = 0;
	if (value >> 32) { value >>= 32; result += 32; }
	if (value >> 16) { value >>= 16; result += 16; }
	if (value >> 8) { value >>= 8; result += 8; }
	if (value >> 4) { value >>= 4; result += 4; }
	if (value >> 2) { value >>= 2; result += 2; }
	if (value >> 1) result += 1;
	return result;
}

static __always_inline struct sc_stat *get_stat(struct sc_key *key)
{
	struct sc_stat *st = bpf_map_lookup_elem(&syscall_stats, key);
	if (st)
		return st;
	struct sc_stat zero = {};
	bpf_map_update_elem(&syscall_stats, key, &zero, BPF_NOEXIST);
	st = bpf_map_lookup_elem(&syscall_stats, key);
	if (!st)
		health_inc(SYSCALL_HEALTH_STAT_UPDATE_FAIL);
	return st;
}

static __always_inline void update_max(__u64 *maximum, __u64 value)
{
	__u64 old = *maximum;
	if (old < value)
		__sync_val_compare_and_swap(maximum, old, value);
}

SEC("tp_btf/sys_enter")
int BPF_PROG(handle_enter, struct pt_regs *regs, long id)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	if (!allowed_tgid(tgid))
		return 0;
	// Seeing a post-attach enter proves any startup marker for this TID is
	// stale; a later missing exit must not be hidden by that marker.
	bpf_map_delete_elem(&startup_tids, &tid);
	struct sc_start value = {
		.ts = bpf_ktime_get_ns(),
		.nr = (__u32)id,
	};
	if (bpf_map_update_elem(&start, &tid, &value, BPF_ANY))
		health_inc(SYSCALL_HEALTH_START_UPDATE_FAIL);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(handle_exit, struct pt_regs *regs, long ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pid_tgid;
	__u32 tgid = pid_tgid >> 32;
	// Do not re-evaluate mutable target membership here. Presence in start is
	// the enter-time eligibility proof; rechecking could leak the entry or lose
	// latency when a child exits between user-space membership refreshes.
	struct sc_start *begin = bpf_map_lookup_elem(&start, &tid);
	if (!begin) {
		if (bpf_map_delete_elem(&startup_tids, &tid) == 0)
			return 0;
		__u32 zero = 0;
		__u32 *target = bpf_map_lookup_elem(&target_pid, &zero);
		if (!target || *target == 0) {
			health_inc(SYSCALL_HEALTH_EXIT_MISS);
		} else {
			__u64 *admitted = bpf_map_lookup_elem(&target_tgids, &tgid);
			struct task_struct *task = bpf_get_current_task_btf();
			__u64 identity = BPF_CORE_READ(task, group_leader, start_boottime);
			// Target descendants are discovered at sys_enter, so admitted
			// instance membership plus no start entry is a real LRU/data-loss
			// miss. A stale key for a reused PID must not fail the collector.
			if (admitted && target_identity_matches(*admitted, identity))
				health_inc(SYSCALL_HEALTH_EXIT_MISS);
		}
		return 0;
	}
	bpf_map_delete_elem(&startup_tids, &tid);

	__u64 now = bpf_ktime_get_ns();
	__u64 duration = now > begin->ts ? now - begin->ts : 0;
	struct sc_key key = {
		.pid = tgid,
		.nr = begin->nr,
	};
	struct sc_stat *st = get_stat(&key);
	if (st) {
		__sync_fetch_and_add(&st->count, 1);
		__sync_fetch_and_add(&st->total_ns, duration);
		update_max(&st->max_ns, duration);
		__u32 slot = log2_u64(duration);
		if (slot >= NSLOTS)
			slot = NSLOTS - 1;
		__sync_fetch_and_add(&st->slots[slot], 1);
		bpf_get_current_comm(&st->comm, sizeof(st->comm));
	}
	bpf_map_delete_elem(&start, &tid);
	return 0;
}
