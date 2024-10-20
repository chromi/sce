// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* DelTiC (Delay Time Control) AQM discipline BOROSHNE
 *
 * Copyright (C) 2019-2024 Jonathan Morton <chromatix99@gmail.com>
 *
 * DelTiC is a fully time-domain AQM based on a delta-sigma control loop and
 * a numerically-controlled oscillator.  Delta-sigma means a PID controller
 * lacking a Proportional term, with the D term accumulated into the I term.
 *
 * BOROSHNE implements an Approximate Fairness scheduler, coupled with a
 * Tetra Queue classifier to divide flows according to their responsiveness.
 *
 * Each of the four queues is set to receive traffic as follows:
 *  - Sparse: flows with at most one packet enqueued, which receive strict priority.
 *      A dummy packet is sent through the Quick queue to regulate this.
 *  - Quick: flows responding to SCE signalling, or which are equivalently responsive.
 *  - Bulk: flows responding to conventional ECN (or drop if Not-ECT) signalling.
 *  - Hog: flows not responding to normal congestion signalling.
 *
 * A deficit-mode shaper is integrated to minimise deployment complexity.
 */

#include <net/pkt_cls.h>
#include <net/gso.h>
#include <net/tcp.h>

#include <net/deltic.h>

#define FREQ_SHIFT (16)
#define TETRA_FLOWS (4096)

struct boroshne_sched_data {
	/* queues */
	struct sk_buff	*sprs_head;	// Sparse
	struct sk_buff	*sprs_tail;
	struct sk_buff	*quik_head;	// Quick
	struct sk_buff	*quik_tail;
	struct sk_buff	*bulk_head;	// Bulk
	struct sk_buff	*bulk_tail;
	struct sk_buff	*hogg_head;	// Hog
	struct sk_buff	*hogg_tail;

	/* AQM params */
	struct deltic_params	sce_params;
	struct deltic_params	ecn_params;
	struct deltic_params	drp_params;

	/* Diffserv configuration */
	u64 bkgd_mask;	// DSCPs to not distinguish by flow
	u64 sce_mask;	// DSCPs to apply SCE marking (if ECT)

	/* Flow & AQM state */
	struct deltic_jitter	jit_vars;
	struct {
		u32 sprs_bklg;
		u32 quik_bklg;
		u32 bulk_bklg;
		u32 hogg_bklg;
		struct deltic_vars	sce_vars;
		struct deltic_vars	ecn_vars;
		struct deltic_vars	drp_vars;
		u8  tgt_queue;
	} flow[TETRA_FLOWS];

	/* Resource tracking */
	u32 sprs_bklg;
	u32 quik_bklg;
	u32 bulk_bklg;
	u32 hogg_bklg;
	u16 sprs_flows;
	u16 quik_flows;
	u16 bulk_flows;
	u16 hogg_flows;
	u64 quik_sojourn;
	u64 bulk_sojourn;
	u64 hogg_sojourn;
	u32 quik_deficit;
	u32 bulk_deficit;
	u32 hogg_deficit;

	/* Shaper state */
	ktime_t	time_next_packet;
	u64	rate_ns;
	u16	rate_shift;
	u16	rate_flags;
	s16	rate_overhead;
	u16	rate_mpu;
	u64	rate_bps;
	struct qdisc_watchdog watchdog;

	/* statistics */
	u64	ce_marks;
	u64	sce_marks;
};



static inline u64 us_to_ns(u64 us)
{
	return us * NSEC_PER_USEC;
}

static inline u64 ns_to_us(u64 ns)
{
	return div64_u64(ns, NSEC_PER_USEC);
}

static inline u64 ms_to_ns(u64 ms)
{
	return ms * NSEC_PER_MSEC;
}

static inline s64 ns_scaled_mul(s64 a, s64 b)
{
	s64 ab = a * b;
	return div64_long(ab, NSEC_PER_SEC);
}

static inline s64 ns_scaled_weight(u64 a, u64 wa, u64 b, u64 wb)
{
	u64 ab = a * wa + b * wb;
	return div64_ul(ab, NSEC_PER_SEC);
}




/* Queues & Flows */

enum {
	TGT_QUICK = 0,
	TGT_BULK,
	TGT_HOG
};

static u32 boroshne_hash(const struct sk_buff *skb)
{
	/* Implements only 5-tuple flow hash, without set association */
	u32 flow_hash = 0;
	struct flow_keys keys;

	skb_flow_dissect_flow_keys(skb, &keys,
				   FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
	flow_hash = flow_hash_from_keys(&keys);

	return flow_hash % TETRA_FLOWS;
}

static inline u32 boroshne_flow_backlog(struct boroshne_sched_data *q, u32 flow)
{
	return
		q->flow[flow].sprs_bklg +
		q->flow[flow].quik_bklg +
		q->flow[flow].bulk_bklg +
		q->flow[flow].hogg_bklg;
}

static inline u32 boroshne_total_backlog(struct boroshne_sched_data *q)
{
	return
		q->sprs_bklg +
		q->quik_bklg +
		q->bulk_bklg +
		q->hogg_bklg;
}

static struct sk_buff* dequeue_hog(struct boroshne_sched_data *q)
{
	struct sk_buff *skb = q->hogg_head;

	if(skb) {
		u16 flow = deltic_get_flow(skb);
		u32 len  = qdisc_pkt_len(skb);

		q->hogg_head = skb->next;
		skb_mark_not_on_list(skb);

		q->hogg_deficit -= len;

		WARN_ON(q->hogg_bklg < len);
		q->hogg_bklg -= len;

		WARN_ON(q->flow[flow].hogg_bklg < len);
		q->flow[flow].hogg_bklg -= len;

		if(!q->flow[flow].hogg_bklg) {
			WARN_ON(!q->hogg_flows);
			q->hogg_flows--;
		}
	}

	return skb;
}

static struct sk_buff* dequeue_bulk(struct boroshne_sched_data *q)
{
	struct sk_buff *skb = q->bulk_head;

	if(skb) {
		u16 flow = deltic_get_flow(skb);
		u32 len  = qdisc_pkt_len(skb);

		q->bulk_head = skb->next;
		skb_mark_not_on_list(skb);

		q->bulk_deficit -= len;

		WARN_ON(q->bulk_bklg < len);
		q->bulk_bklg -= len;

		WARN_ON(q->flow[flow].bulk_bklg < len);
		q->flow[flow].bulk_bklg -= len;

		if(!q->flow[flow].bulk_bklg) {
			WARN_ON(!q->bulk_flows);
			q->bulk_flows--;
		}
	}

	return skb;
}

static struct sk_buff* dequeue_quick(struct boroshne_sched_data *q)
{
	struct sk_buff *skb = q->quik_head;

	if(skb) {
		u16 flow = deltic_get_flow(skb);
		u32 len  = qdisc_pkt_len(skb);

		q->quik_head = skb->next;
		skb_mark_not_on_list(skb);

		if(deltic_is_sparse(skb)) {
			// dummy packet
			kfree_skb(skb);
			return dequeue_quick(q);
		}

		q->quik_deficit -= len;

		WARN_ON(q->quik_bklg < len);
		q->quik_bklg -= len;

		WARN_ON(q->flow[flow].quik_bklg < len);
		q->flow[flow].quik_bklg -= len;

		if(!q->flow[flow].quik_bklg) {
			WARN_ON(!q->quik_flows);
			q->quik_flows--;
		}
	}

	return skb;
}

static struct sk_buff* dequeue_sparse(struct boroshne_sched_data *q)
{
	struct sk_buff *skb = q->sprs_head;

	if(skb) {
		u16 flow = deltic_get_flow(skb);
		u32 len  = qdisc_pkt_len(skb);

		q->sprs_head = skb->next;
		skb_mark_not_on_list(skb);

		WARN_ON(q->sprs_bklg < len);
		q->sprs_bklg -= len;

		WARN_ON(q->flow[flow].sprs_bklg < len);
		q->flow[flow].sprs_bklg -= len;

		if(!q->flow[flow].sprs_bklg) {
			WARN_ON(!q->sprs_flows);
			q->sprs_flows--;
		}
	}

	return skb;
}

static void enqueue_hog(struct boroshne_sched_data *q, struct sk_buff *skb)
{
	u16 flow = deltic_get_flow(skb);
	u32 len  = qdisc_pkt_len(skb);

	if(!q->flow[flow].hogg_bklg)
		q->hogg_flows++;
	q->flow[flow].hogg_bklg += len;
	q->hogg_bklg += len;

	if (!q->hogg_head)
		q->hogg_head = skb;
	else
		q->hogg_tail->next = skb;
	q->hogg_tail = skb;
	skb->next = NULL;
}

static void enqueue_bulk(struct boroshne_sched_data *q, struct sk_buff *skb)
{
	u16 flow = deltic_get_flow(skb);
	u32 len  = qdisc_pkt_len(skb);

	if(!q->flow[flow].bulk_bklg)
		q->bulk_flows++;
	q->flow[flow].bulk_bklg += len;
	q->bulk_bklg += len;

	if (!q->bulk_head)
		q->bulk_head = skb;
	else
		q->bulk_tail->next = skb;
	q->bulk_tail = skb;
	skb->next = NULL;
}

static void enqueue_quick(struct boroshne_sched_data *q, struct sk_buff *skb)
{
	if(!deltic_is_sparse(skb)) {
		u16 flow = deltic_get_flow(skb);
		u32 len  = qdisc_pkt_len(skb);

		if(!q->flow[flow].quik_bklg)
			q->quik_flows++;
		q->flow[flow].quik_bklg += len;
		q->quik_bklg += len;
	}

	if (!q->quik_head)
		q->quik_head = skb;
	else
		q->quik_tail->next = skb;
	q->quik_tail = skb;
	skb->next = NULL;
}

static void enqueue_sparse(struct boroshne_sched_data *q, struct sk_buff *skb)
{
	u16 flow = deltic_get_flow(skb);
	u32 len  = qdisc_pkt_len(skb);
	struct sk_buff *cskb;

	/* In parallel, enqueue a dummy packet into the quick queue. */
	cskb = skb_clone(skb, GFP_ATOMIC);
	if (likely(cskb)) {
		deltic_set_cb_sparse(cskb, deltic_get_enqueue_time(skb), flow);
		enqueue_quick(q, cskb);
	} else {
		/* allocation failure, fall back to using the quick queue */
		enqueue_quick(q, skb);
		return;
	}

	if(!q->flow[flow].sprs_bklg)
		q->sprs_flows++;
	q->flow[flow].sprs_bklg += len;
	q->sprs_bklg += len;

	if (!q->sprs_head)
		q->sprs_head = skb;
	else
		q->sprs_tail->next = skb;
	q->sprs_tail = skb;
	skb->next = NULL;
}


/* Approximate Fairness, also used by Tetra Queue logic */
static u64 boroshne_effective_sojourn(struct boroshne_sched_data *q, u32 flow)
{
	u64 quik_sojourn=0, bulk_sojourn=0, hogg_sojourn=0;

	// For each queue, the "effective sojourn time" for the AQM is the actual
	// sojourn time multiplied by the ratio of the flow's occupancy relative
	// to its fair-share occupancy.  The latter is the total backlog divided
	// by the number of flows.
	//
	// effective_sojourn = queue_sojourn * flow_bklg * flows / total_bklg
	//
	// This would be easy to calculate in floating-point, but there is a
	// non-trivial risk of overflow if done in fixed-point.
	// FIXME: figure out how much of a problem this actually is.

	if(q->flow[flow].quik_bklg)
		quik_sojourn = div64_ul(q->quik_sojourn * q->flow[flow].quik_bklg * q->quik_flows, q->quik_bklg);
	if(q->flow[flow].bulk_bklg)
		bulk_sojourn = div64_ul(q->bulk_sojourn * q->flow[flow].bulk_bklg * q->bulk_flows, q->bulk_bklg);
	if(q->flow[flow].hogg_bklg)
		hogg_sojourn = div64_ul(q->hogg_sojourn * q->flow[flow].hogg_bklg * q->hogg_flows, q->hogg_bklg);

	return quik_sojourn + bulk_sojourn + hogg_sojourn;
}


/* Deficit-mode Shaper */
#define SHAPER_FLAG_OVERHEAD (0x01)
#define SHAPER_FLAG_ATM      (0x10)
#define SHAPER_FLAG_PTM      (0x20)

static u32 shaper_calc_overhead(struct boroshne_sched_data *q, u32 len, u32 off)
{
	if (q->rate_flags & SHAPER_FLAG_OVERHEAD)
		len -= off;
	len += q->rate_overhead;
	if (len < q->rate_mpu)
		len = q->rate_mpu;

	if (q->rate_flags & SHAPER_FLAG_ATM) {
		len += 47;
		len /= 48;
		len *= 53;
	} else if (q->rate_flags & SHAPER_FLAG_PTM) {
		len += (len + 63) / 64;
	}
	return len;
}

static u32 shaper_overhead(struct boroshne_sched_data *q, const struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int hdr_len, last_len = 0;
	u32 off = skb_network_offset(skb);
	u32 len = qdisc_pkt_len(skb);
	u16 segs = 1;

	if (!shinfo->gso_size)
		return shaper_calc_overhead(q, len, off);

	/* borrowed from qdisc_pkt_len_init() */
	hdr_len = skb_transport_offset(skb);

	/* + transport layer */
	if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))) {
		const struct tcphdr *th;
		struct tcphdr _tcphdr;

		th = skb_header_pointer(skb, hdr_len,
		sizeof(_tcphdr), &_tcphdr);
		if (likely(th))
			hdr_len += __tcp_hdrlen(th);
	} else {
		struct udphdr _udphdr;

		if (skb_header_pointer(skb, hdr_len,
				       sizeof(_udphdr), &_udphdr))
		hdr_len += sizeof(struct udphdr);
	}

	if (unlikely(shinfo->gso_type & SKB_GSO_DODGY))
		segs = DIV_ROUND_UP(skb->len - hdr_len,
				    shinfo->gso_size);
	else
		segs = shinfo->gso_segs;

	len = shinfo->gso_size + hdr_len;
	last_len = skb->len - shinfo->gso_size * (segs - 1);

	return (shaper_calc_overhead(q, len, off) * (segs - 1) +
		shaper_calc_overhead(q, last_len, off));
}

static int boroshne_advance_shaper(struct boroshne_sched_data *q,
			      struct sk_buff *skb,
			      ktime_t now)
{
	u32 len = shaper_overhead(q, skb);

	if (q->rate_ns) {
		u64 global_dur = (len * q->rate_ns) >> q->rate_shift;

		q->time_next_packet = ktime_add_ns(q->time_next_packet,
						   global_dur);
	}
	return len;
}

static void boroshne_unstale_shaper(struct boroshne_sched_data *q, ktime_t now)
{
	if (!boroshne_total_backlog(q)) {
		if (ktime_after(q->time_next_packet, now))
			qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
		else
			q->time_next_packet = now;
	}
}


/* Core */

static s32 boroshne_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);
	int len = qdisc_pkt_len(skb);
	ktime_t now = ktime_get();
	u32 flow;

	if(!sch->q.qlen)  // queue just became non-empty
		q->jit_vars.timestamp = now;

	/* GSO splitting */
	if (skb_is_gso(skb)) {
		struct sk_buff *segs, *nskb;
		netdev_features_t features = netif_skb_features(skb);
		unsigned int slen = 0, numsegs = 0;

		segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
		if (IS_ERR_OR_NULL(segs))
			return qdisc_drop(skb, sch, to_free);

		skb_list_walk_safe(segs, segs, nskb) {
			skb_mark_not_on_list(segs);

			qdisc_skb_cb(segs)->pkt_len = segs->len;
			slen += segs->len;
			numsegs++;

			boroshne_enqueue(segs, sch, to_free);
		}

		qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen);
		consume_skb(skb);

		return NET_XMIT_SUCCESS;
	}

	/* prepare and enqueue */
	flow = boroshne_hash(skb);
	deltic_set_cb(skb, now, flow);
	boroshne_unstale_shaper(q, now);

	/* direct packet to the appropriate queue */
	if(boroshne_flow_backlog(q, flow)) {
		if(q->flow[flow].tgt_queue == TGT_HOG)
			enqueue_hog(q, skb);
		else if(q->flow[flow].tgt_queue == TGT_BULK)
			enqueue_bulk(q, skb);
		else
			enqueue_quick(q, skb);
	} else {
		enqueue_sparse(q, skb);
	}

	sch->q.qlen++;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* boroshne_dequeue(struct Qdisc *sch)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get(), enq_time;
	struct sk_buff *skb;
	u32 len, flow;
	u64 jitter, sojourn;
	u64 *queue_sojourn = 0;
	bool mark_sce, mark_ecn, drop;
	bool quik_blocked, bulk_blocked, hogg_blocked;
	bool quik_avail, bulk_avail, hogg_avail;
	bool any_blocked, any_avail;

	if(!sch->q.qlen)
		return NULL;

	/* shaper */
	if (ktime_after(q->time_next_packet, now)) {
		sch->qstats.overlimits++;
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
		return NULL;
	}

	/* Sparse queue has strict priority */
	/* Weighted Deficit Round Robin between Quick, Bulk, Hog queues */
	quik_blocked = q->quik_bklg && q->quik_deficit < 0;
	bulk_blocked = q->bulk_bklg && q->bulk_deficit < 0;
	hogg_blocked = q->hogg_bklg && q->hogg_deficit < 0;
	any_blocked = quik_blocked || bulk_blocked || hogg_blocked;

	quik_avail = q->quik_bklg && q->quik_deficit >= 0;
	bulk_avail = q->bulk_bklg && q->bulk_deficit >= 0;
	hogg_avail = q->hogg_bklg && q->hogg_deficit >= 0;
	any_avail = quik_avail || bulk_avail || hogg_avail;

	if(any_blocked && !any_avail) {
		// all queues with waiting traffic have deficits
		// replenish them proportionally to flow occupancy
		/*
		u32 quik_inc = q->quik_flows;
		u32 bulk_inc = q->bulk_flows;
		u32 hogg_inc = q->hogg_flows;

		WARN_ON(q->quik_bklg && !q->quik_flows);
		WARN_ON(q->bulk_bklg && !q->bulk_flows);
		WARN_ON(q->hogg_bklg && !q->hogg_flows);

		WARN_ON(q->quik_flows && !q->quik_bklg);
		WARN_ON(q->bulk_flows && !q->bulk_bklg);
		WARN_ON(q->hogg_flows && !q->hogg_bklg);

		while(	(quik_blocked && ((s32) quik_inc) < -q->quik_deficit) ||
				(bulk_blocked && ((s32) bulk_inc) < -q->bulk_deficit) ||
				(hogg_blocked && ((s32) hogg_inc) < -q->hogg_deficit) )
		{
			quik_inc *= 2;
			bulk_inc *= 2;
			hogg_inc *= 2;
		}

		q->quik_deficit += quik_inc;
		q->bulk_deficit += bulk_inc;
		q->hogg_deficit += hogg_inc;
		*/

		s32 max_deficit = 0;

		if(q->quik_flows && q->quik_deficit < max_deficit)
			max_deficit = q->quik_deficit;
		if(q->bulk_flows && q->bulk_deficit < max_deficit)
			max_deficit = q->bulk_deficit;
		if(q->hogg_flows && q->hogg_deficit < max_deficit)
			max_deficit = q->hogg_deficit;

		q->quik_deficit -= max_deficit * q->quik_flows;
		q->bulk_deficit -= max_deficit * q->bulk_flows;
		q->hogg_deficit -= max_deficit * q->hogg_flows;
	}

	/* Dequeue in priority order from queues not in deficit */
	skb = dequeue_sparse(q);
	if (!skb && q->quik_deficit >= 0) {
		skb = dequeue_quick(q);
		queue_sojourn = &q->quik_sojourn;
	}
	if (!skb && q->bulk_deficit >= 0) {
		skb = dequeue_bulk(q);
		queue_sojourn = &q->bulk_sojourn;
	}
	if (!skb && q->hogg_deficit >= 0) {
		skb = dequeue_hog(q);
		queue_sojourn = &q->hogg_sojourn;
	}
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	flow = deltic_get_flow(skb);
	len = qdisc_pkt_len(skb);
	sch->q.qlen--;

	/* AQM */
	enq_time = deltic_get_enqueue_time(skb);
	jitter   = deltic_jitter_estimate(&q->jit_vars, now);
	sojourn  = deltic_correct_sojourn(enq_time, now, jitter);

	if(queue_sojourn) {
		*queue_sojourn = sojourn;
		sojourn = boroshne_effective_sojourn(q, flow);

		// update flow direction based on effective sojourn time
		// apply promotion thresholds with hysteresis, based on which AQM they respond to
		if(q->flow[flow].tgt_queue == TGT_HOG && sojourn < q->ecn_params.target)
			q->flow[flow].tgt_queue = TGT_BULK;
		if(q->flow[flow].tgt_queue == TGT_BULK && sojourn < q->sce_params.target)
			q->flow[flow].tgt_queue = TGT_QUICK;

		if(q->flow[flow].tgt_queue == TGT_QUICK && sojourn > q->sce_params.target * 2)
			q->flow[flow].tgt_queue = TGT_BULK;
		if(q->flow[flow].tgt_queue == TGT_BULK && sojourn > q->ecn_params.target * 2)
			q->flow[flow].tgt_queue = TGT_HOG;
	}

	mark_sce = q->sce_params.resonance && deltic_control(&q->flow[flow].sce_vars, &q->sce_params, now, sojourn);
	mark_ecn = q->ecn_params.resonance && deltic_control(&q->flow[flow].ecn_vars, &q->ecn_params, now, sojourn);
	drop     = q->drp_params.resonance && deltic_control(&q->flow[flow].drp_vars, &q->drp_params, now, sojourn);

	if(mark_sce && !mark_ecn && !drop)
		if(INET_ECN_set_ect1(skb))
			q->sce_marks++;

	if(mark_ecn && !drop) {
		if(INET_ECN_set_ce(skb))
			q->ce_marks++;
		else
			drop = true;
	}

	/* Never drop the last queued packet for a flow. */
	if(drop && boroshne_flow_backlog(q, flow)) {
		/* drop packet, and try again with the next one */
		qdisc_tree_reduce_backlog(sch, 1, len);
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return boroshne_dequeue(sch);
	}
	qdisc_bstats_update(sch, skb);

	/* shaper again */
	boroshne_advance_shaper(q, skb, now);
	if (ktime_after(q->time_next_packet, now) && sch->q.qlen)
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);

	return skb;
}


/* Configuration */

static const struct nla_policy boroshne_policy[TCA_DELTIC_MAX + 1] = {
	[TCA_DELTIC_FREQ_DROP]		= { .type = NLA_U32 },  // resonance frequency (16.16) for drop controller
	[TCA_DELTIC_FREQ_ECN]		= { .type = NLA_U32 },  // resonance frequency (16.16) for ECN controller
	[TCA_DELTIC_FREQ_SCE]		= { .type = NLA_U32 },  // resonance frequency (16.16) for SCE controller
//	[TCA_DELTIC_FREQ_SIGNAL]	= { .type = NLA_U32 },  // baseline signalling frequency for all controllers
	[TCA_DELTIC_BASE_RATE64]	= { .type = NLA_U64 },
	[TCA_DELTIC_ATM]			= { .type = NLA_U8 },
	[TCA_DELTIC_OVERHEAD]		= { .type = NLA_S8 },
	[TCA_DELTIC_RAW]			= { .type = NLA_FLAG },
	[TCA_DELTIC_MPU]			= { .type = NLA_U16 },
};

static void boroshne_parameterise(struct deltic_params *p, const u32 res_freq)
{
	p->resonance = res_freq;

	if(res_freq)
		p->target = div64_ul(NSEC_PER_SEC * (1ULL << FREQ_SHIFT), res_freq);
	else
		p->target = NSEC_PER_SEC;
}

static int boroshne_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_DELTIC_MAX + 1];
	int err;

	err = nla_parse_nested(tb, TCA_DELTIC_MAX, opt, boroshne_policy, extack);
	if (err < 0)
		return err;

	if (tb[TCA_DELTIC_FREQ_DROP])
		boroshne_parameterise(&q->drp_params, nla_get_u32(tb[TCA_DELTIC_FREQ_DROP]));

	if (tb[TCA_DELTIC_FREQ_ECN])
		boroshne_parameterise(&q->ecn_params, nla_get_u32(tb[TCA_DELTIC_FREQ_ECN]));

	if (tb[TCA_DELTIC_FREQ_SCE])
		boroshne_parameterise(&q->sce_params, nla_get_u32(tb[TCA_DELTIC_FREQ_SCE]));

	if (tb[TCA_DELTIC_BASE_RATE64])
		q->rate_bps = nla_get_u64(tb[TCA_DELTIC_BASE_RATE64]);

	if (tb[TCA_DELTIC_ATM]) {
		q->rate_flags &= ~(SHAPER_FLAG_ATM | SHAPER_FLAG_PTM);
		switch(nla_get_u8(tb[TCA_DELTIC_ATM])) {
		case CAKE_ATM_ATM:
			q->rate_flags |= SHAPER_FLAG_ATM;
			break;

		case CAKE_ATM_PTM:
			q->rate_flags |= SHAPER_FLAG_PTM;
			break;

		default:;
		};
	}

	if (tb[TCA_DELTIC_OVERHEAD]) {
		q->rate_overhead = nla_get_s8(tb[TCA_DELTIC_OVERHEAD]);
		q->rate_flags |= SHAPER_FLAG_OVERHEAD;
	}

	if (tb[TCA_DELTIC_RAW] && nla_get_flag(tb[TCA_DELTIC_RAW]))
		q->rate_flags &= ~SHAPER_FLAG_OVERHEAD;

	if (tb[TCA_DELTIC_MPU])
		q->rate_mpu = nla_get_u16(tb[TCA_DELTIC_MPU]);

	if(!q->rate_bps) {
		/* unlimited mode */
		q->rate_ns = q->rate_shift = 0;
		sch->flags |= TCQ_F_CAN_BYPASS;
	} else {
		/* convert bytes per second into nanoseconds per byte */
		u8  rate_shft = 34;
		u64 rate_ns = 0;

		rate_ns = ((u64)NSEC_PER_SEC) << rate_shft;
		rate_ns = div64_u64(rate_ns, max(64ULL, q->rate_bps));
		while(!!(rate_ns >> 34)) {
			rate_ns >>= 1;
			rate_shft--;
		}
		q->rate_ns = rate_ns;
		q->rate_shift = rate_shft;

		sch->flags &= ~TCQ_F_CAN_BYPASS;
	}

	return 0;
}

static int boroshne_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_DELTIC_FREQ_DROP, q->drp_params.resonance))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_DELTIC_FREQ_ECN, q->ecn_params.resonance))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_DELTIC_FREQ_SCE, q->sce_params.resonance))
		goto nla_put_failure;


	if (nla_put_u64_64bit(skb, TCA_DELTIC_BASE_RATE64, q->rate_bps, TCA_DELTIC_PAD))
		goto nla_put_failure;

	if (nla_put_s8(skb, TCA_DELTIC_OVERHEAD, q->rate_overhead))
		goto nla_put_failure;

	if (!(q->rate_flags & SHAPER_FLAG_OVERHEAD))
		if (nla_put_flag(skb, TCA_DELTIC_RAW))
			goto nla_put_failure;

	if (nla_put_u8(skb, TCA_DELTIC_ATM,
	                q->rate_flags & SHAPER_FLAG_ATM ? CAKE_ATM_ATM :
	                q->rate_flags & SHAPER_FLAG_PTM ? CAKE_ATM_PTM :
	                0))
		goto nla_put_failure;

	if (nla_put_u16(skb, TCA_DELTIC_MPU, q->rate_mpu))
		goto nla_put_failure;


	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int boroshne_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct nlattr *stats = nla_nest_start_noflag(d->skb, TCA_STATS_APP);
	struct boroshne_sched_data *q = qdisc_priv(sch);

	if (!stats)
		return -1;

#define PUT_STAT_U32(attr, data) do {                             \
	if (nla_put_u32(d->skb, TCA_DELTIC_STATS_ ## attr, data)) \
		goto nla_put_failure;                             \
	} while (0)

#define PUT_STAT_U64(attr, data) do {                             \
	if (nla_put_u64_64bit(d->skb, TCA_DELTIC_STATS_ ## attr,  \
				data, TCA_DELTIC_STATS_PAD))      \
		goto nla_put_failure;                             \
	} while (0)

	PUT_STAT_U32(JITTER_EST, ns_to_us(q->jit_vars.jitter));
	PUT_STAT_U64(SCE_MARKS,  q->sce_marks);
	PUT_STAT_U64( CE_MARKS,  q-> ce_marks);
//	PUT_STAT_U64(AQM_DROPS,  q->);

#undef PUT_STAT_U32
#undef PUT_STAT_U64

	return nla_nest_end(d->skb, stats);

nla_put_failure:
	nla_nest_cancel(d->skb, stats);
	return -1;
}

static int boroshne_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	sch->limit = 10240;

	qdisc_watchdog_init(&q->watchdog, sch);

	boroshne_parameterise(&q->drp_params,   8 << FREQ_SHIFT);  // 125ms target for hard dropping
	boroshne_parameterise(&q->ecn_params,  40 << FREQ_SHIFT);  //  25ms target for ECN marking
	boroshne_parameterise(&q->sce_params, 200 << FREQ_SHIFT);  //   5ms target for SCE marking

	if (opt) {
		int err = boroshne_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static void boroshne_reset(struct Qdisc *sch)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	while (!!(skb = dequeue_sparse(q)))
		kfree_skb(skb);
	while (!!(skb = dequeue_quick(q)))
		kfree_skb(skb);
	while (!!(skb = dequeue_bulk(q)))
		kfree_skb(skb);
	while (!!(skb = dequeue_hog(q)))
		kfree_skb(skb);

	sch->q.qlen = 0;
}

static void boroshne_destroy(struct Qdisc *sch)
{
	struct boroshne_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
}


static struct Qdisc_ops boroshne_qdisc_ops __read_mostly = {
	.id		=	"deltic_boroshne",
	.priv_size	=	sizeof(struct boroshne_sched_data),
	.enqueue	=	boroshne_enqueue,
	.dequeue	=	boroshne_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.change		=	boroshne_change,
	.dump		=	boroshne_dump,
	.dump_stats	=	boroshne_dump_stats,
	.init		=	boroshne_init,
	.reset		=	boroshne_reset,
	.destroy	=	boroshne_destroy,
	.owner		=	THIS_MODULE,
};

static int __init boroshne_module_init(void)
{
	return register_qdisc(&boroshne_qdisc_ops);
}

static void __exit boroshne_module_exit(void)
{
	unregister_qdisc(&boroshne_qdisc_ops);
}

module_init(boroshne_module_init)
module_exit(boroshne_module_exit)
MODULE_AUTHOR("Jonathan Morton");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("DelTiC-BOROSHNE - Delay Time Control AF/TQ qdisc.");
