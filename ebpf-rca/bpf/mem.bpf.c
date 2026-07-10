// SPDX-License-Identifier: GPL-2.0
//
// Memory-pressure evidence.  Direct reclaim is attributed to the allocating
// process; mark_victim is the authoritative OOM event.  PSI, vmstat, faults
// and RSS rates are sampled in user space so the BPF hot path stays small.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define TARGET_PROC_START_SEED (1ULL << 63)
#define TARGET_PROC_START_MASK (TARGET_PROC_START_SEED - 1)
#define NS_PER_USER_TICK 10000000ULL

enum mem_health_index {
	MEM_HEALTH_RECLAIM_START_UPDATE_FAIL,
	MEM_HEALTH_RECLAIM_END_MISS,
	MEM_HEALTH_STAT_UPDATE_FAIL,
	MEM_HEALTH_OOM_UPDATE_FAIL,
	MEM_HEALTH_TARGET_UPDATE_FAIL,
	MEM_HEALTH_MAX,
};

struct mem_stat {
	__u64 direct_reclaim_count;
	__u64 direct_reclaim_ns;
	char comm[TASK_COMM_LEN];
};

struct reclaim_info {
	__u64 ts;
	__u32 tgid;
	__u32 pad;
};

struct oom_stat {
	__u64 count;
	__u32 uid;
	__u8 in_target;
	__u8 pad[3];
	char comm[TASK_COMM_LEN];
};

// tid -> direct-reclaim start.  A per-thread key prevents sibling threads
// from overwriting one another.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct reclaim_info);
} reclaim_start SEC(".maps");

// Seeded after direct-reclaim begin is attached and before end is attached.
// It distinguishes a pre-attach reclaim end from a true lost begin entry.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} startup_tids SEC(".maps");

// tgid -> cumulative direct-reclaim statistics.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct mem_stat);
} mem_stats SEC(".maps");

// tgid -> cumulative OOM-victim events.  Keeping this separate from reclaim
// makes an OOM event independently and immediately detectable.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct oom_stat);
} oom_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} kswapd_wakes SEC(".maps");

// Target membership is refreshed by user space.  OOM victims may disappear
// from /proc before the next poll, so target membership must be captured at
// the event rather than reconstructed afterwards.
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} observed_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MEM_HEALTH_MAX);
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

static __always_inline bool in_target(__u32 tgid, struct task_struct *task)
{
	__u32 key = 0;
	__u32 *target = bpf_map_lookup_elem(&target_pid, &key);
	if (!target || *target == 0)
		return true;
	__u64 identity = BPF_CORE_READ(task, group_leader, start_boottime);
	__u64 *admitted = bpf_map_lookup_elem(&target_tgids, &tgid);
	if (admitted && target_identity_matches(*admitted, identity)) {
		bool seeded = *admitted & TARGET_PROC_START_SEED;
		if (seeded && bpf_map_update_elem(&target_tgids, &tgid, &identity, BPF_ANY))
			health_inc(MEM_HEALTH_TARGET_UPDATE_FAIL);
		__u64 *seen = bpf_map_lookup_elem(&observed_tgids, &tgid);
		if ((!seen || *seen != identity) &&
		    bpf_map_update_elem(&observed_tgids, &tgid, &identity, BPF_ANY))
			health_inc(MEM_HEALTH_TARGET_UPDATE_FAIL);
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
				health_inc(MEM_HEALTH_TARGET_UPDATE_FAIL);
			return true;
		}
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		if (!parent || parent == task)
			break;
		task = parent;
	}
	return false;
}

static __always_inline struct mem_stat *get_mem_stat(__u32 tgid)
{
	struct mem_stat *st = bpf_map_lookup_elem(&mem_stats, &tgid);
	if (st)
		return st;
	struct mem_stat zero = {};
	bpf_map_update_elem(&mem_stats, &tgid, &zero, BPF_NOEXIST);
	st = bpf_map_lookup_elem(&mem_stats, &tgid);
	if (!st)
		health_inc(MEM_HEALTH_STAT_UPDATE_FAIL);
	return st;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_direct_begin(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	struct reclaim_info info = {
		.ts = bpf_ktime_get_ns(),
		.tgid = id >> 32,
	};
	bpf_map_delete_elem(&startup_tids, &tid);
	// Record short-lived target descendants even though reclaim aggregation is
	// intentionally global and user space applies the final scope filter.
	(void)in_target(info.tgid, bpf_get_current_task_btf());
	if (bpf_map_update_elem(&reclaim_start, &tid, &info, BPF_ANY))
		health_inc(MEM_HEALTH_RECLAIM_START_UPDATE_FAIL);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int handle_direct_end(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	__u32 tgid = id >> 32;
	__u64 now = bpf_ktime_get_ns();
	struct reclaim_info *info = bpf_map_lookup_elem(&reclaim_start, &tid);
	if (!info) {
		if (bpf_map_delete_elem(&startup_tids, &tid) < 0)
			health_inc(MEM_HEALTH_RECLAIM_END_MISS);
		return 0;
	}
	bpf_map_delete_elem(&startup_tids, &tid);
	tgid = info->tgid;

	struct mem_stat *st = get_mem_stat(tgid);
	if (st) {
		__sync_fetch_and_add(&st->direct_reclaim_count, 1);
		if (now > info->ts)
			__sync_fetch_and_add(&st->direct_reclaim_ns, now - info->ts);
		bpf_get_current_comm(&st->comm, sizeof(st->comm));
	}
	bpf_map_delete_elem(&reclaim_start, &tid);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_kswapd_wake")
int handle_kswapd_wake(void *ctx)
{
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&kswapd_wakes, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	return 0;
}

SEC("tp_btf/mark_victim")
int BPF_PROG(handle_mark_victim, struct task_struct *task, uid_t uid)
{
	__u32 tgid = BPF_CORE_READ(task, tgid);
	if (!tgid)
		tgid = BPF_CORE_READ(task, pid);
	if (!tgid)
		return 0;
	__u8 targeted = in_target(tgid, task);

	struct oom_stat *st = bpf_map_lookup_elem(&oom_stats, &tgid);
	if (!st) {
		struct oom_stat zero = {
			.uid = uid,
			.in_target = targeted,
		};
		bpf_core_read_str(&zero.comm, sizeof(zero.comm), &task->comm);
		bpf_map_update_elem(&oom_stats, &tgid, &zero, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&oom_stats, &tgid);
		if (!st) {
			health_inc(MEM_HEALTH_OOM_UPDATE_FAIL);
			return 0;
		}
	}
	if (st) {
		__sync_fetch_and_add(&st->count, 1);
		st->uid = uid;
		st->in_target = targeted;
		bpf_core_read_str(&st->comm, sizeof(st->comm), &task->comm);
	}
	return 0;
}
