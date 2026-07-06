// SPDX-License-Identifier: GPL-2.0
//
// 场景⑤：高频 / 高耗时系统调用热点（赛题唯一未给测试脚本的场景，差异化项）。
//
// 思路（关键证据点：syscall 频次 Top-N、单次耗时、累计耗时占比、发起进程/线程）：
//   raw_syscalls:sys_enter 记录线程进入 syscall 的时间与号；
//   raw_syscalls:sys_exit  结算单次耗时，按 (进程, syscall号) 累计次数/总耗时/最大耗时。
// 用通用 raw_syscalls tracepoint，跨 syscall ABI 可移植；syscall 号→名在用户态解析。
//
// 注意：raw_syscalls 触发极频繁，是本工具开销最高的场景。生产可经 target_pid
// 过滤(见 design.md 扩展点)只观测目标进程以降开销。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct sc_start {
	__u64 ts;
	__u32 nr;
	__u32 pad;
};

struct sc_key {
	__u32 pid; // tgid
	__u32 nr;  // syscall number
};

struct sc_stat {
	__u64 count;
	__u64 total_ns;
	__u64 max_ns;
	char  comm[TASK_COMM_LEN];
};

// tid -> 本次 syscall 起点
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u32);
	__type(value, struct sc_start);
} start SEC(".maps");

// (pid, nr) -> 累计统计
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct sc_key);
	__type(value, struct sc_stat);
} syscall_stats SEC(".maps");

struct sys_enter_tp {
	__u64 pad;
	__s64 id;
	__u64 args[6];
};

struct sys_exit_tp {
	__u64 pad;
	__s64 id;
	__s64 ret;
};

static __always_inline struct sc_stat *get_stat(struct sc_key *k)
{
	struct sc_stat *st = bpf_map_lookup_elem(&syscall_stats, k);
	if (st)
		return st;
	struct sc_stat zero = {};
	bpf_map_update_elem(&syscall_stats, k, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&syscall_stats, k);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_enter(struct sys_enter_tp *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct sc_start s = {};
	s.ts = bpf_ktime_get_ns();
	s.nr = (__u32)ctx->id;
	bpf_map_update_elem(&start, &tid, &s, BPF_ANY);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_exit(struct sys_exit_tp *ctx)
{
	__u64 idpid = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)idpid;
	struct sc_start *s = bpf_map_lookup_elem(&start, &tid);
	if (!s)
		return 0;

	__u64 dur = bpf_ktime_get_ns() - s->ts;
	struct sc_key k = {};
	k.pid = idpid >> 32;
	k.nr = s->nr;

	struct sc_stat *st = get_stat(&k);
	if (st) {
		__sync_fetch_and_add(&st->count, 1);
		__sync_fetch_and_add(&st->total_ns, dur);
		if (dur > st->max_ns)
			st->max_ns = dur;
		bpf_get_current_comm(&st->comm, sizeof(st->comm));
	}
	bpf_map_delete_elem(&start, &tid);
	return 0;
}
