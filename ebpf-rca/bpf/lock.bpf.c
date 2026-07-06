// SPDX-License-Identifier: GPL-2.0
//
// 场景④：锁竞争导致的性能退化 —— 基于 off-CPU 阻塞分析 + 唤醒链。
//
// 思路（赛题关键证据点：锁等待时间、调度阻塞时间、线程堆栈聚集、futex 热点）：
//   1. sched_switch 中 prev_state != 0（非 RUNNING，即"被阻塞切出"而非"被抢占"）时，
//      记录该线程的 off-CPU 起点，并抓取其内核调用栈（阻塞点，如 futex_wait/__mutex_lock）。
//   2. 该线程重新上 CPU 时，结算阻塞时长，按线程累计 off-CPU 阻塞时间/次数/最大值，并记下阻塞栈 id。
//   3. sched_wakeup 中记录"唤醒者"——构成 waker→wakee 唤醒链，定位是谁持锁阻塞了它。
// 内核态仅聚合，栈符号化在用户态用 /proc/kallsyms 完成，开销低。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN  16
#define MAX_STACK_DEPTH 32

struct lock_stat {
	__u64 offcpu_ns;     // 累计阻塞型 off-CPU 时间
	__u64 offcpu_count;  // 阻塞次数
	__u64 max_offcpu_ns; // 单次最长阻塞
	__u32 last_waker;    // 最近一次唤醒者 tid
	__s32 stackid;       // 最近一次阻塞的内核栈 id
	char  comm[TASK_COMM_LEN];
};

struct offcpu_info {
	__u64 ts;
	__s32 stackid;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct offcpu_info);
} offcpu_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct lock_stat);
} lock_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stackmap SEC(".maps");

struct sched_switch_tp {
	__u64 pad;
	char  prev_comm[TASK_COMM_LEN];
	__s32 prev_pid;
	__s32 prev_prio;
	__s64 prev_state;
	char  next_comm[TASK_COMM_LEN];
	__s32 next_pid;
	__s32 next_prio;
};

struct sched_wakeup_tp {
	__u64 pad;
	char  comm[TASK_COMM_LEN];
	__s32 pid;
	__s32 prio;
	__s32 target_cpu;
};

static __always_inline struct lock_stat *get_stat(__u32 tid)
{
	struct lock_stat *st = bpf_map_lookup_elem(&lock_stats, &tid);
	if (st)
		return st;
	struct lock_stat zero = {};
	bpf_map_update_elem(&lock_stats, &tid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&lock_stats, &tid);
}

SEC("tracepoint/sched/sched_switch")
int handle_switch(struct sched_switch_tp *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 prev = (__u32)ctx->prev_pid;
	__u32 next = (__u32)ctx->next_pid;

	// prev 因阻塞被切出（prev_state != 0 表示非 RUNNING，排除普通抢占）
	if (prev != 0 && ctx->prev_state != 0) {
		struct offcpu_info info = {};
		info.ts = now;
		info.stackid = bpf_get_stackid(ctx, &stackmap, 0);
		bpf_map_update_elem(&offcpu_start, &prev, &info, BPF_ANY);
	}

	// next 回到 CPU：结算阻塞时长
	if (next != 0) {
		struct offcpu_info *info = bpf_map_lookup_elem(&offcpu_start, &next);
		if (info && now > info->ts) {
			__u64 dur = now - info->ts;
			struct lock_stat *st = get_stat(next);
			if (st) {
				st->offcpu_ns += dur;
				st->offcpu_count += 1;
				if (dur > st->max_offcpu_ns)
					st->max_offcpu_ns = dur;
				st->stackid = info->stackid;
				bpf_probe_read_kernel_str(&st->comm, sizeof(st->comm),
							  ctx->next_comm);
			}
			bpf_map_delete_elem(&offcpu_start, &next);
		}
	}
	return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_wakeup(struct sched_wakeup_tp *ctx)
{
	__u32 wakee = (__u32)ctx->pid;
	if (wakee == 0)
		return 0;
	// 唤醒发生在唤醒者上下文：current 即 waker
	__u32 waker = (__u32)bpf_get_current_pid_tgid();
	struct lock_stat *st = get_stat(wakee);
	if (st)
		st->last_waker = waker;
	return 0;
}
