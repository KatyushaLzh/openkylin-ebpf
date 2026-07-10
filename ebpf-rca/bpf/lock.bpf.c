// SPDX-License-Identifier: GPL-2.0
//
// Lock/synchronisation wait attribution.  sched_switch supplies the precise
// voluntary-vs-preempted distinction, while do_futex fentry/fexit brackets a
// futex operation so a sleep can be attributed to its user-space address.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 32
#define LOCK_NSLOTS 48
#define FUTEX_CMD_MASK 0x7f
#define FUTEX_WAIT 0
#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_BITSET 9
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_LOCK_PI2 13
#define FUTEX_OP_NONE ((__u32)-1)
#define LOCK_TASK_UNINTERRUPTIBLE 0x00000002U
#define TARGET_PROC_START_SEED (1ULL << 63)
#define TARGET_PROC_START_MASK (TARGET_PROC_START_SEED - 1)
#define NS_PER_USER_TICK 10000000ULL

enum lock_health_index {
	LOCK_HEALTH_FUTEX_UPDATE_FAIL,
	LOCK_HEALTH_OFFCPU_UPDATE_FAIL,
	LOCK_HEALTH_STAT_UPDATE_FAIL,
	LOCK_HEALTH_STACK_FAIL,
	LOCK_HEALTH_TARGET_UPDATE_FAIL,
	LOCK_HEALTH_MAX,
};

struct futex_info {
	__u64 lock_address;
	__u32 op;
	__u32 pad;
};

struct offcpu_info {
	__u64 ts;
	__u64 lock_address;
	// Per-thread start_boottime prevents a stale TID entry from being
	// completed by a later thread that reused the same numeric TID.
	__u64 task_identity;
	__u32 tgid;
	__u32 tid;
	__s32 stackid;
	__u32 futex_op;
	__u32 last_waker;
	__u32 pad;
};

// A per-thread key keeps exact waiter evidence in BPF.  User space groups
// futex records by (tgid, lock_address), and address-less kernel waits by
// (tgid, stackid).
struct lock_key {
	__u32 tgid;
	__u32 tid;
	__u64 lock_address;
	__s32 stackid;
	__u32 futex_op;
};

struct lock_stat {
	__u64 offcpu_ns;
	__u64 offcpu_count;
	__u32 last_waker;
	__u32 pad;
	char comm[TASK_COMM_LEN];
	__u64 slots[LOCK_NSLOTS];
};

// tid -> active do_futex wait operation.
struct {
	// Silent LRU eviction would make health look clean while losing the
	// futex address needed for attribution. A full HASH fails the update and
	// is surfaced through LOCK_HEALTH_FUTEX_UPDATE_FAIL.
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct futex_info);
} futex_active SEC(".maps");

// tid -> current voluntary off-CPU interval.
struct {
	// Keep capacity loss observable via LOCK_HEALTH_OFFCPU_UPDATE_FAIL.
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct offcpu_info);
} offcpu_start SEC(".maps");

struct {
	// Stats must never disappear without a health signal: user space relies on
	// cumulative deltas when certifying a clean observation window.
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct lock_key);
	__type(value, struct lock_stat);
} lock_stats SEC(".maps");

// A map-backed immutable zero template keeps the 424-byte lock_stat out of
// sched_switch's 512-byte BPF stack. Each CPU gets its own value so the lookup
// is verifier-safe without introducing cross-CPU sharing; the value is never
// modified by a program.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct lock_stat);
} lock_stat_zero SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stackmap SEC(".maps");

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
	// Exact group_leader->start_boottime or a high-bit-marked /proc USER_HZ
	// seed binds membership to a process instance. A matching seed is upgraded
	// to exact nanoseconds by the lighter futex/wakeup hooks.
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
	__uint(max_entries, LOCK_HEALTH_MAX);
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

static __always_inline bool allowed_task(__u32 tgid, struct task_struct *task)
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
			health_inc(LOCK_HEALTH_TARGET_UPDATE_FAIL);
		__u64 *seen = bpf_map_lookup_elem(&observed_tgids, &tgid);
		if ((!seen || *seen != identity) &&
		    bpf_map_update_elem(&observed_tgids, &tgid, &identity, BPF_ANY))
			health_inc(LOCK_HEALTH_TARGET_UPDATE_FAIL);
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
				health_inc(LOCK_HEALTH_TARGET_UPDATE_FAIL);
			return true;
		}
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		if (!parent || parent == task)
			break;
		task = parent;
	}
	return false;
}

// sched_switch is already close to the 512-byte verifier stack boundary
// because it builds stack and aggregation keys.  Keep this lookup in the
// caller's frame: a BPF-to-BPF call would make the verifier add the rounded
// stack depth of both frames and reject the program even though each frame is
// individually smaller than MAX_BPF_STACK. Descendant discovery happens at
// the lighter futex/wakeup hooks; this hot path only consults membership.
static __always_inline bool admitted_task(__u32 tgid, struct task_struct *task)
{
	__u32 key = 0;
	__u32 *target = bpf_map_lookup_elem(&target_pid, &key);
	if (!target || *target == 0)
		return true;
	__u64 *identity = bpf_map_lookup_elem(&target_tgids, &tgid);
	__u64 task_identity = BPF_CORE_READ(task, group_leader, start_boottime);
	return identity && target_identity_matches(*identity, task_identity);
}

static __always_inline bool futex_op_can_wait(__u32 op)
{
	switch (op & FUTEX_CMD_MASK) {
	case FUTEX_WAIT:
	case FUTEX_LOCK_PI:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_LOCK_PI2:
		return true;
	default:
		return false;
	}
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

static __always_inline struct lock_stat *get_lock_stat(struct lock_key *key)
{
	struct lock_stat *st = bpf_map_lookup_elem(&lock_stats, key);
	if (st)
		return st;
	__u32 zero_key = 0;
	struct lock_stat *zero = bpf_map_lookup_elem(&lock_stat_zero, &zero_key);
	if (!zero) {
		health_inc(LOCK_HEALTH_STAT_UPDATE_FAIL);
		return 0;
	}
	bpf_map_update_elem(&lock_stats, key, zero, BPF_NOEXIST);
	st = bpf_map_lookup_elem(&lock_stats, key);
	if (!st)
		health_inc(LOCK_HEALTH_STAT_UPDATE_FAIL);
	return st;
}

SEC("fentry/do_futex")
int BPF_PROG(handle_futex_enter, u32 *uaddr, int op, u32 val,
	     ktime_t *timeout, u32 *uaddr2, u32 val2, u32 val3)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	__u32 tgid = id >> 32;
	struct task_struct *task = bpf_get_current_task_btf();
	if (!allowed_task(tgid, task) || !futex_op_can_wait(op))
		return 0;
	struct futex_info info = {
		.lock_address = (__u64)uaddr,
		.op = (__u32)op,
	};
	if (bpf_map_update_elem(&futex_active, &tid, &info, BPF_ANY))
		health_inc(LOCK_HEALTH_FUTEX_UPDATE_FAIL);
	return 0;
}

SEC("fexit/do_futex")
int BPF_PROG(handle_futex_exit, u32 *uaddr, int op, u32 val,
		     ktime_t *timeout, u32 *uaddr2, u32 val2, u32 val3,
		     long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&futex_active, &tid);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, unsigned int prev_state)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 prev_tid = BPF_CORE_READ(prev, pid);
	__u32 prev_tgid = BPF_CORE_READ(prev, tgid);
	__u32 next_tid = BPF_CORE_READ(next, pid);
	__u32 next_tgid = BPF_CORE_READ(next, tgid);
	int prev_exit_state = BPF_CORE_READ(prev, exit_state);

	// A RUNNING task can voluntarily yield, and preempt=true is an involuntary
	// switch.  Neither is evidence of a lock/synchronisation wait.
	if (prev_tid && prev_state != 0 && !preempt && prev_exit_state == 0 &&
	    admitted_task(prev_tgid, prev)) {
		struct futex_info *futex = bpf_map_lookup_elem(&futex_active, &prev_tid);
		// Address-less kernel synchronization waits are normally
		// uninterruptible (TASK_KILLABLE includes this bit). Skip ordinary
		// interruptible sleeps such as epoll/read before paying stack cost.
		if (!futex && !(prev_state & LOCK_TASK_UNINTERRUPTIBLE))
			goto account_next;
		struct offcpu_info info = {
			.ts = now,
			.task_identity = BPF_CORE_READ(prev, start_boottime),
			.tgid = prev_tgid,
			.tid = prev_tid,
			.futex_op = FUTEX_OP_NONE,
		};
		info.stackid = bpf_get_stackid(ctx, &stackmap, 0);
		if (info.stackid < 0)
			health_inc(LOCK_HEALTH_STACK_FAIL);
		if (futex) {
			info.lock_address = futex->lock_address;
			info.futex_op = futex->op;
		}
		if (bpf_map_update_elem(&offcpu_start, &prev_tid, &info, BPF_ANY))
			health_inc(LOCK_HEALTH_OFFCPU_UPDATE_FAIL);
	}

account_next:
	if (next_tid) {
		struct offcpu_info *info = bpf_map_lookup_elem(&offcpu_start, &next_tid);
		__u64 next_identity = BPF_CORE_READ(next, start_boottime);
		if (info && (info->tgid != next_tgid ||
			     info->task_identity != next_identity)) {
			// TID reuse: never charge the old wait interval to the new task.
			bpf_map_delete_elem(&offcpu_start, &next_tid);
			return 0;
		}
		if (info && now > info->ts) {
			__u64 duration = now - info->ts;
			struct lock_key key = {
				.tgid = info->tgid,
				.tid = info->tid,
				.lock_address = info->lock_address,
				.stackid = info->stackid,
				.futex_op = info->futex_op,
			};
			struct lock_stat *st = get_lock_stat(&key);
			if (st) {
				__sync_fetch_and_add(&st->offcpu_ns, duration);
				__sync_fetch_and_add(&st->offcpu_count, 1);
				__u32 slot = log2_u64(duration);
				if (slot >= LOCK_NSLOTS)
					slot = LOCK_NSLOTS - 1;
				__sync_fetch_and_add(&st->slots[slot], 1);
				st->last_waker = info->last_waker;
				bpf_core_read_str(&st->comm, sizeof(st->comm), &next->comm);
			}
			bpf_map_delete_elem(&offcpu_start, &next_tid);
		}
	}
	return 0;
}

static __always_inline int record_wakeup(struct task_struct *task)
{
	__u32 wakee = BPF_CORE_READ(task, pid);
	__u32 wakee_tgid = BPF_CORE_READ(task, tgid);
	(void)allowed_task(wakee_tgid, task);
	if (!wakee)
		return 0;
	struct offcpu_info *info = bpf_map_lookup_elem(&offcpu_start, &wakee);
	if (info)
		info->last_waker = (__u32)bpf_get_current_pid_tgid();
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_wakeup, struct task_struct *task)
{
	return record_wakeup(task);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_wakeup_new, struct task_struct *task)
{
	return record_wakeup(task);
}
