// SPDX-License-Identifier: GPL-2.0
//
// 场景③：内存抖动 / OOM 风险 —— 基于 vmscan tracepoint 的回收压力归因。
//
// 思路（赛题关键证据点：内存使用率、major/minor fault、kswapd 活跃度、回收次数）：
//   mm_vmscan_direct_reclaim_begin/end：进程在分配内存时被迫"直接回收"(direct reclaim)，
//       这是内存压力最直接、危害最大的信号。按进程(tgid)累计直接回收次数与耗时，
//       并以 current 归因——谁在分配内存把系统逼到直接回收。
//   mm_vmscan_kswapd_wake：后台回收线程 kswapd 被唤醒次数(全局)，反映整体回收活跃度。
// 这些 tracepoint 跨架构可移植、字段无关(本程序不读字段)，开销极低。
// 内存使用率与 per-process 缺页(major/minor fault) 由用户态读 /proc 补充，避免高频 kprobe 开销。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct mem_stat {
	__u64 direct_reclaim_count; // 直接回收次数
	__u64 direct_reclaim_ns;    // 直接回收累计耗时
	char  comm[TASK_COMM_LEN];
};

// tgid -> 直接回收开始时间戳
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} reclaim_start SEC(".maps");

// tgid -> 累计统计
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct mem_stat);
} mem_stats SEC(".maps");

// 单槽全局计数：kswapd 唤醒次数
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} kswapd_wakes SEC(".maps");

static __always_inline struct mem_stat *get_stat(__u32 tgid)
{
	struct mem_stat *st = bpf_map_lookup_elem(&mem_stats, &tgid);
	if (st)
		return st;
	struct mem_stat zero = {};
	bpf_map_update_elem(&mem_stats, &tgid, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&mem_stats, &tgid);
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_direct_begin(void *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&reclaim_start, &tgid, &now, BPF_ANY);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int handle_direct_end(void *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 now = bpf_ktime_get_ns();
	__u64 *tsp = bpf_map_lookup_elem(&reclaim_start, &tgid);

	struct mem_stat *st = get_stat(tgid);
	if (st) {
		st->direct_reclaim_count += 1;
		if (tsp && now > *tsp)
			st->direct_reclaim_ns += now - *tsp;
		bpf_get_current_comm(&st->comm, sizeof(st->comm));
	}
	if (tsp)
		bpf_map_delete_elem(&reclaim_start, &tgid);
	return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_kswapd_wake")
int handle_kswapd_wake(void *ctx)
{
	__u32 key = 0;
	__u64 *c = bpf_map_lookup_elem(&kswapd_wakes, &key);
	if (c)
		__sync_fetch_and_add(c, 1);
	return 0;
}
