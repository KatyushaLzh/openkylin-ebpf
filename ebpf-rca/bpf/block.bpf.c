// SPDX-License-Identifier: GPL-2.0
//
// 场景②：I/O 延迟抖动 / 阻塞等待 —— 基于块层 tracepoint 的请求时延分析。
//
// 思路（赛题关键证据点：IOPS、平均时延、P99 时延、队列深度、热点设备）：
//   block_rq_issue   ：请求下发到设备时记录起点（按 dev+sector+nr_sector+rwbs 索引），队列深度++。
//   block_rq_complete：请求完成时命中起点才算单次时延并扣队列深度；按设备累计
//                      次数/总时延/最大时延/字节数，并落入 log2 时延直方图(供算 P99)，队列深度--。
// 内核态仅聚合，用户态按窗口差分并从直方图估算 P99，开销低。
//
// 注意：tracepoint 字段偏移随内核版本可能变化。如遇异常，请用
//   cat /sys/kernel/tracing/events/block/block_rq_issue/format
// 核对 dev/sector/nr_sector 的布局。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define NSLOTS 32 // log2(ns) 直方图槽位，2^31 ns ≈ 2.1s

struct dev_stat {
	__u64 count;        // 完成请求数
	__u64 total_lat_ns; // 累计时延
	__u64 max_lat_ns;   // 最大时延
	__u64 bytes;        // 累计字节数(吞吐)
	__s64 inflight;     // 当前在途请求数(队列深度,gauge)
	__u64 slots[NSLOTS];// 时延 log2 直方图
};

struct rq_key {
	__u32 dev;
	__u32 nr_sector;
	__u64 sector;
	char  rwbs[8];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct rq_key);
	__type(value, __u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct dev_stat);
} dev_stats SEC(".maps");

// block_rq_issue tracepoint 上下文（含 common 头 8 字节）
struct block_rq_issue_tp {
	__u64 pad;
	__u32 dev;
	__u32 _pad0;
	__u64 sector;
	__u32 nr_sector;
	__u32 bytes;
	char  rwbs[8];
	char  comm[16];
};

// block_rq_complete tracepoint 上下文
struct block_rq_complete_tp {
	__u64 pad;
	__u32 dev;
	__u32 _pad0;
	__u64 sector;
	__u32 nr_sector;
	__s32 error;
	char  rwbs[8];
};

static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 r = 0;
#pragma unroll
	for (int i = 0; i < 64; i++) {
		if (v <= 1)
			break;
		v >>= 1;
		r++;
	}
	return r;
}

static __always_inline struct dev_stat *get_dev(__u32 dev)
{
	struct dev_stat *d = bpf_map_lookup_elem(&dev_stats, &dev);
	if (d)
		return d;
	struct dev_stat zero = {};
	bpf_map_update_elem(&dev_stats, &dev, &zero, BPF_NOEXIST);
	return bpf_map_lookup_elem(&dev_stats, &dev);
}

static __always_inline struct rq_key make_key(__u32 dev, __u64 sector, __u32 nr_sector, const char rwbs[8])
{
	struct rq_key k = {};
	k.dev = dev;
	k.nr_sector = nr_sector;
	k.sector = sector;
#pragma unroll
	for (int i = 0; i < 8; i++)
		k.rwbs[i] = rwbs[i];
	return k;
}

SEC("tracepoint/block/block_rq_issue")
int handle_issue(struct block_rq_issue_tp *ctx)
{
	struct rq_key k = make_key(ctx->dev, ctx->sector, ctx->nr_sector, ctx->rwbs);
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &k, &ts, BPF_ANY);

	struct dev_stat *d = get_dev(ctx->dev);
	if (d)
		__sync_fetch_and_add(&d->inflight, 1);
	return 0;
}

SEC("tracepoint/block/block_rq_complete")
int handle_complete(struct block_rq_complete_tp *ctx)
{
	struct rq_key k = make_key(ctx->dev, ctx->sector, ctx->nr_sector, ctx->rwbs);
	__u64 *tsp = bpf_map_lookup_elem(&start, &k);
	if (!tsp)
		return 0;

	struct dev_stat *d = get_dev(ctx->dev);
	if (!d) {
		bpf_map_delete_elem(&start, &k);
		return 0;
	}

	__sync_fetch_and_add(&d->inflight, -1);

	__u64 now = bpf_ktime_get_ns();
	__u64 delta = now - *tsp;
	bpf_map_delete_elem(&start, &k);

	__sync_fetch_and_add(&d->count, 1);
	__sync_fetch_and_add(&d->total_lat_ns, delta);
	__sync_fetch_and_add(&d->bytes, (__u64)ctx->nr_sector * 512);
	if (delta > d->max_lat_ns)
		d->max_lat_ns = delta; // best-effort gauge

	__u32 slot = log2_u64(delta);
	if (slot >= NSLOTS)
		slot = NSLOTS - 1;
	__sync_fetch_and_add(&d->slots[slot], 1);
	return 0;
}
