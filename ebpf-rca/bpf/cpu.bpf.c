// SPDX-License-Identifier: GPL-2.0
//
// 场景①：CPU 异常占用 / 调度延迟 采集探针 (CO-RE, libbpf)
//
// 通过 sched_switch / sched_wakeup 两个稳定 ABI tracepoint，按线程(tid)聚合：
//   - run_ns ：累计在 CPU 上运行的时间   -> 计算 CPU 占用率
//   - runq_ns：累计在运行队列等待的时间   -> 计算调度等待时间
//   - ctx    ：被切出 CPU 的次数          -> 计算上下文切换频次
// 这些正是赛题"CPU 异常场景"列出的关键证据点。
// 内核态只做聚合，用户态按窗口读取并做差分，开销极低（无 per-event 上送）。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct task_stat {
	__u64 run_ns;   // 累计在 CPU 上运行的纳秒数
	__u64 runq_ns;  // 累计运行队列等待纳秒数
	__u64 ctx;      // 上下文切换(被切出)次数
	char  comm[TASK_COMM_LEN];
};

// tid -> 本次上 CPU 的时间戳
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} oncpu_start SEC(".maps");

// tid -> 被唤醒(入队)的时间戳
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} wakeup_ts SEC(".maps");

// tid -> 累计统计
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct task_stat);
} stats SEC(".maps");

// tracepoint 上下文布局（稳定 ABI，直接读取，无需 CO-RE 重定位）
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

static __always_inline struct task_stat *get_stat(__u32 tid)
{
	struct task_stat *st = bpf_map_lookup_elem(&stats, &tid);
	if (st)
		return st;
	struct task_stat zero = {};
	bpf_map_update_elem(&stats, &tid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&stats, &tid);
}

SEC("tracepoint/sched/sched_wakeup")
int handle_wakeup(struct sched_wakeup_tp *ctx)
{
	__u32 tid = (__u32)ctx->pid;
	if (tid == 0)
		return 0;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&wakeup_ts, &tid, &now, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int handle_switch(struct sched_switch_tp *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 prev = (__u32)ctx->prev_pid;
	__u32 next = (__u32)ctx->next_pid;

	// prev 被切出 CPU：累计运行时间与切换次数
	if (prev != 0) {
		__u64 *ts = bpf_map_lookup_elem(&oncpu_start, &prev);
		struct task_stat *st = get_stat(prev);
		if (st) {
			if (ts && now > *ts)
				st->run_ns += now - *ts;
			st->ctx += 1;
			bpf_probe_read_kernel_str(&st->comm, sizeof(st->comm),
						  ctx->prev_comm);
		}
	}

	// next 上 CPU：记录起点；若有唤醒时间戳则累计运行队列等待
	if (next != 0) {
		bpf_map_update_elem(&oncpu_start, &next, &now, BPF_ANY);
		__u64 *wts = bpf_map_lookup_elem(&wakeup_ts, &next);
		if (wts && now > *wts) {
			struct task_stat *st = get_stat(next);
			if (st)
				st->runq_ns += now - *wts;
			bpf_map_delete_elem(&wakeup_ts, &next);
		}
	}
	return 0;
}
