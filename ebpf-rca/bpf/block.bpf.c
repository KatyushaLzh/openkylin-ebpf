// SPDX-License-Identifier: GPL-2.0
//
// Block I/O collector. Kernel 6.6+BTF is a hard requirement. The request
// pointer is the request identity; sector tuples are not unique under merged
// or concurrent I/O and therefore cannot safely match issue to completion.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define NSLOTS 40

struct request_state {
	__u64 first_issue_ns;
	__u64 total_bytes;
	__u64 completed_bytes;
	__u64 successful_bytes;
	__u32 dev;
	// Requests issued while user space completes the two-hook startup handshake
	// still need exact completion matching, but must not contaminate metrics.
	__u32 tracked;
};

// The spin lock protects queue-area integration and all per-device counters.
// queue_area_ns has units request*ns.
struct dev_stat {
	struct bpf_spin_lock lock;
	__u32 pad;
	__u64 count;
	__u64 total_lat_ns;
	__u64 bytes;
	__u64 queue_area_ns;
	__u64 queue_last_ns;
	__s64 inflight;
	__u64 slots[NSLOTS];
};

struct health_stat {
	__u64 duplicate_issue;
	__u64 completion_miss;
	__u64 map_update_fail;
	__u64 partial_completion;
	__u64 io_error;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct request *);
	__type(value, struct request_state);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct dev_stat);
} dev_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct health_stat);
} health SEC(".maps");

// Zero-initialized and set by user space only after completion was attached
// before issue. The value and a non-zero request.start_time_ns share
// CLOCK_MONOTONIC; Linux resets that field on each timestamped allocation.
// Zero means startup classification is ambiguous and is conservatively
// suppressed. Do not use io_start_time_ns: Linux writes it after rq_issue.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} startup_boundary_ns SEC(".maps");

static __always_inline __u64 startup_boundary(void)
{
	__u32 zero = 0;
	__u64 *boundary = bpf_map_lookup_elem(&startup_boundary_ns, &zero);
	return boundary ? *boundary : 0;
}

static __always_inline struct health_stat *get_health(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&health, &zero);
}

static __always_inline void health_inc(__u64 *counter)
{
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

static __always_inline __u32 request_dev(struct request *rq)
{
	// Queue depth is a property of the whole request_queue. Match the block
	// tracepoint's disk_devt(rq->q->disk) identity instead of splitting one
	// hardware queue by partition.
	int major = BPF_CORE_READ(rq, q, disk, major);
	int minor = BPF_CORE_READ(rq, q, disk, first_minor);
	return ((__u32)major << 20) | ((__u32)minor & 0xfffff);
}

static __always_inline __u32 latency_slot(__u64 ns)
{
	__u32 slot = 0;
	if (ns >> 32) { ns >>= 32; slot += 32; }
	if (ns >> 16) { ns >>= 16; slot += 16; }
	if (ns >> 8) { ns >>= 8; slot += 8; }
	if (ns >> 4) { ns >>= 4; slot += 4; }
	if (ns >> 2) { ns >>= 2; slot += 2; }
	if (ns >> 1) slot += 1;
	if (slot >= NSLOTS)
		slot = NSLOTS - 1;
	return slot;
}

static __always_inline struct dev_stat *get_dev(__u32 dev, __u64 now)
{
	struct dev_stat *d = bpf_map_lookup_elem(&dev_stats, &dev);
	if (d)
		return d;

	struct dev_stat zero = {};
	zero.queue_last_ns = now;
	if (bpf_map_update_elem(&dev_stats, &dev, &zero, BPF_NOEXIST) < 0) {
		// Another CPU may have won initialization. EEXIST is healthy; only
		// count failure when the value is still unavailable after re-lookup.
		d = bpf_map_lookup_elem(&dev_stats, &dev);
		if (!d) {
			struct health_stat *h = get_health();
			health_inc(h ? &h->map_update_fail : 0);
		}
		return d;
	}
	return bpf_map_lookup_elem(&dev_stats, &dev);
}

static __always_inline void account_queue_locked(struct dev_stat *d, __u64 now)
{
	if (d->queue_last_ns && now > d->queue_last_ns && d->inflight > 0)
		d->queue_area_ns += (now - d->queue_last_ns) * (__u64)d->inflight;
	d->queue_last_ns = now;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(handle_issue, struct request *rq)
{
	if (!rq)
		return 0;

	struct health_stat *h = get_health();
	if (bpf_map_lookup_elem(&start, &rq)) {
		health_inc(h ? &h->duplicate_issue : 0);
		return 0;
	}

	__u64 now = bpf_ktime_get_ns();
	struct request_state state = {
		.first_issue_ns = now,
		.total_bytes = BPF_CORE_READ(rq, __data_len),
		.dev = request_dev(rq),
		.tracked = startup_boundary() != 0,
	};
	if (bpf_map_update_elem(&start, &rq, &state, BPF_NOEXIST) < 0) {
		health_inc(h ? &h->map_update_fail : 0);
		return 0;
	}

	if (!state.tracked)
		return 0;

	struct dev_stat *d = get_dev(state.dev, now);
	if (!d)
		return 0;
	bpf_spin_lock(&d->lock);
	account_queue_locked(d, now);
	d->inflight++;
	bpf_spin_unlock(&d->lock);
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(handle_complete, struct request *rq, blk_status_t error,
	     unsigned int nr_bytes)
{
	if (!rq)
		return 0;

	struct health_stat *h = get_health();
	struct request_state *state = bpf_map_lookup_elem(&start, &rq);
	if (!state) {
		__u64 boundary = startup_boundary();
		__u64 allocated = BPF_CORE_READ(rq, start_time_ns);
		if (boundary && allocated && allocated >= boundary)
			health_inc(h ? &h->completion_miss : 0);
		return 0;
	}

	__u64 completed = state->completed_bytes + (__u64)nr_bytes;
	__u64 remaining = BPF_CORE_READ(rq, __data_len);
	if (state->tracked && error)
		health_inc(h ? &h->io_error : 0);
	else if (state->tracked)
		state->successful_bytes += (__u64)nr_bytes;
	// trace_block_rq_complete runs before blk_update_request advances rq, so
	// __data_len is the authoritative remaining byte count at this event.
	if ((__u64)nr_bytes < remaining) {
		state->completed_bytes = completed;
		if (state->tracked)
			health_inc(h ? &h->partial_completion : 0);
		return 0;
	}

	// Copy before deleting: map-value pointers become invalid after delete.
	struct request_state done = *state;
	done.completed_bytes = completed;
	__u64 now = bpf_ktime_get_ns();
	__u64 latency_ns = now > done.first_issue_ns ? now - done.first_issue_ns : 0;
	bpf_map_delete_elem(&start, &rq);
	if (!done.tracked)
		return 0;

	struct dev_stat *d = bpf_map_lookup_elem(&dev_stats, &done.dev);
	if (!d) {
		health_inc(h ? &h->map_update_fail : 0);
		return 0;
	}
	__u32 slot = latency_slot(latency_ns);
	bpf_spin_lock(&d->lock);
	account_queue_locked(d, now);
	if (d->inflight > 0)
		d->inflight--;
	d->count++;
	d->total_lat_ns += latency_ns;
	__u64 accounted_bytes = done.successful_bytes;
	if (accounted_bytes > done.total_bytes)
		accounted_bytes = done.total_bytes;
	d->bytes += accounted_bytes;
	d->slots[slot]++;
	bpf_spin_unlock(&d->lock);
	return 0;
}
