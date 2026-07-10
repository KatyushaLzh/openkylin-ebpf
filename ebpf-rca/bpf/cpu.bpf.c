// SPDX-License-Identifier: GPL-2.0
//
// CPU / scheduler collector. Kernel 6.6+BTF is a hard requirement: typed
// tracepoints give us task_struct (and therefore TGID) and sched_switch's
// explicit preempt argument without relying on tracepoint byte offsets.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 32
#define LONG_RUN_NS (5ULL * 1000 * 1000)

struct task_key {
	__u32 tgid;
	__u32 tid;
};

struct task_stat {
	__u64 run_ns;
	__u64 runq_ns;
	__u64 runq_count;
	__u64 ctx;
	char comm[TASK_COMM_LEN];
};

struct oncpu_info {
	struct task_key task;
	__u64 start_ns;
};

struct stack_key {
	__u32 tgid;
	__u32 tid;
	__s32 stackid;
	__u32 pad;
};

struct stack_stat {
	__u64 count;
	__u64 run_ns;
};

struct health_stat {
	__u64 map_update_fail;
	__u64 stack_capture_fail;
};

// tid -> the current on-CPU interval. A live tid is unique system-wide.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct oncpu_info);
} oncpu_start SEC(".maps");

// tid -> earliest enqueue timestamp. NOEXIST preserves the first enqueue when
// duplicate wakeups are observed.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} enqueue_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct task_key);
	__type(value, struct task_stat);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 8192);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} user_stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct stack_key);
	__type(value, struct stack_stat);
} stack_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct health_stat);
} health SEC(".maps");

static __always_inline void health_inc(__u64 *counter)
{
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

static __always_inline struct health_stat *get_health(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&health, &zero);
}

static __always_inline struct task_key task_key_from(struct task_struct *task)
{
	struct task_key key = {};
	key.tgid = BPF_CORE_READ(task, tgid);
	key.tid = BPF_CORE_READ(task, pid);
	return key;
}

static __always_inline struct task_stat *get_stat(const struct task_key *key)
{
	struct task_stat *st = bpf_map_lookup_elem(&stats, key);
	if (st)
		return st;

	struct task_stat zero = {};
	if (bpf_map_update_elem(&stats, key, &zero, BPF_NOEXIST) < 0) {
		// A concurrent initializer may have won; retry before declaring a
		// capacity/update failure.
		st = bpf_map_lookup_elem(&stats, key);
		if (!st) {
			struct health_stat *h = get_health();
			health_inc(h ? &h->map_update_fail : 0);
		}
		return st;
	}
	return bpf_map_lookup_elem(&stats, key);
}

static __always_inline void record_enqueue(struct task_struct *task, __u64 now)
{
	__u32 tid = BPF_CORE_READ(task, pid);
	if (!tid || bpf_map_lookup_elem(&enqueue_ts, &tid))
		return;
	if (bpf_map_update_elem(&enqueue_ts, &tid, &now, BPF_NOEXIST) < 0) {
		// A concurrent wakeup/requeue may have installed the same earliest
		// timestamp. Count only a real capacity/update loss.
		if (!bpf_map_lookup_elem(&enqueue_ts, &tid)) {
			struct health_stat *h = get_health();
			health_inc(h ? &h->map_update_fail : 0);
		}
	}
}

static __always_inline void record_long_run(void *ctx,
					    const struct task_key *key,
					    __u64 run_ns)
{
	if (run_ns < LONG_RUN_NS)
		return;

	__s32 stackid = bpf_get_stackid(ctx, &user_stacks, BPF_F_USER_STACK);
	if (stackid < 0) {
		struct health_stat *h = get_health();
		health_inc(h ? &h->stack_capture_fail : 0);
		return;
	}

	struct stack_key skey = {
		.tgid = key->tgid,
		.tid = key->tid,
		.stackid = stackid,
	};
	struct stack_stat *sst = bpf_map_lookup_elem(&stack_stats, &skey);
	if (!sst) {
		struct stack_stat zero = {};
		if (bpf_map_update_elem(&stack_stats, &skey, &zero, BPF_NOEXIST) < 0) {
			struct health_stat *h = get_health();
			health_inc(h ? &h->map_update_fail : 0);
			return;
		}
		sst = bpf_map_lookup_elem(&stack_stats, &skey);
	}
	if (sst) {
		__sync_fetch_and_add(&sst->count, 1);
		__sync_fetch_and_add(&sst->run_ns, run_ns);
	}
}

static __always_inline int wakeup(struct task_struct *task)
{
	if (task)
		record_enqueue(task, bpf_ktime_get_ns());
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_wakeup, struct task_struct *task)
{
	return wakeup(task);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_wakeup_new, struct task_struct *task)
{
	return wakeup(task);
}

// A task that was already running when sched_switch attached can otherwise
// remain invisible indefinitely on an isolated/sole-runnable CPU. A low-rate
// per-CPU software perf event seeds only missing intervals; sched_switch keeps
// ownership of exact completion accounting and safely overwrites the seed on
// the next switch-in.
SEC("perf_event")
int handle_seed_oncpu(struct bpf_perf_event_data *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)id;
	if (!tid || bpf_map_lookup_elem(&oncpu_start, &tid))
		return 0;

	struct task_key key = {
		.tgid = id >> 32,
		.tid = tid,
	};
	struct task_stat *st = get_stat(&key);
	if (st)
		bpf_get_current_comm(&st->comm, sizeof(st->comm));

	struct oncpu_info info = {
		.task = key,
		.start_ns = bpf_ktime_get_ns(),
	};
	if (bpf_map_update_elem(&oncpu_start, &tid, &info, BPF_NOEXIST) < 0 &&
	    !bpf_map_lookup_elem(&oncpu_start, &tid)) {
		struct health_stat *h = get_health();
		health_inc(h ? &h->map_update_fail : 0);
	}
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(handle_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, unsigned int prev_state)
{
	__u64 now = bpf_ktime_get_ns();
	struct task_key prev_key = task_key_from(prev);
	struct task_key next_key = task_key_from(next);

	if (prev_key.tid) {
		struct oncpu_info *info = bpf_map_lookup_elem(&oncpu_start,
							      &prev_key.tid);
		struct task_stat *st = get_stat(&prev_key);
		if (st) {
			if (info && now > info->start_ns) {
				__u64 run_ns = now - info->start_ns;
				__sync_fetch_and_add(&st->run_ns, run_ns);
				if (BPF_CORE_READ(prev, mm))
					record_long_run(ctx, &prev_key, run_ns);
			}
			__sync_fetch_and_add(&st->ctx, 1);
			BPF_CORE_READ_STR_INTO(&st->comm, prev, comm);
		}
		bpf_map_delete_elem(&oncpu_start, &prev_key.tid);

		// TASK_RUNNING (0) means the task remains runnable. This covers
		// explicit preemption as well as scheduler-driven requeueing.
		if (preempt || prev_state == 0)
			record_enqueue(prev, now);
	}

	if (next_key.tid) {
		struct task_stat *st = get_stat(&next_key);
		__u64 *queued = bpf_map_lookup_elem(&enqueue_ts, &next_key.tid);
		if (st) {
			BPF_CORE_READ_STR_INTO(&st->comm, next, comm);
			if (queued) {
				if (now > *queued)
					__sync_fetch_and_add(&st->runq_ns, now - *queued);
				__sync_fetch_and_add(&st->runq_count, 1);
			}
		}
		if (queued)
			bpf_map_delete_elem(&enqueue_ts, &next_key.tid);

		struct oncpu_info info = {
			.task = next_key,
			.start_ns = now,
		};
		if (bpf_map_update_elem(&oncpu_start, &next_key.tid, &info,
					BPF_ANY) < 0) {
			struct health_stat *h = get_health();
			health_inc(h ? &h->map_update_fail : 0);
		}
	}
	return 0;
}
