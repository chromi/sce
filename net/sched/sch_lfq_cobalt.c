// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Lightweight Fair Queueing with COBALT discipline
 *
 * Copyright (C) 2019 Jonathan Morton <chromatix99@gmail.com>
 * Copyright (C) 2019 Pete Heist <pete@heistp.net>
 *
 * This is a very lightweight form of flow-aware queuing, with a built-in
 * deficit-mode shaper and AQM.  The flow-isolation performance will be
 * somewhat inferior to true FQ algorithms like DRR++ (as used in fq_codel
 * and CAKE), but the implementation complexity and CPU overhead should be
 * considerably lower.  This software implementation is intended to show
 * performance with a view to future hardware implementation.
 *
 * Unlike conventional fair queueing, with Lightweight Fair Queueing, packets
 * are not distributed to queues by a flow mapping, but by a sparseness metric
 * associated with that mapping.  Thus, the number of queues is reduced to
 * two, the sparse queue and the bulk queue.
 *
 * The "sparse queue" handles flows classed as sparse, including the first
 * packets in newly active flows.  This queue tends to remain short and drain
 * quickly, which are ideal characteristics for latency-sensitive traffic, and
 * young flows still establishing connections or probing for capacity.  This
 * queue does not maintain AQM state nor apply AQM signals.
 *
 * The "bulk queue" handles all traffic not classed as sparse, including at
 * least the second and subsequent packets in a burst.  The bulk queue has not
 * only the typical "head" and "tail", but also a "scan" pointer which
 * iterates over the packets in the queue from head to tail.  Packets are
 * delivered from the "scan" position, not from the "head"; this is key to the
 * capacity-sharing mechanism.  A full set of AQM state is maintained on the
 * bulk queue, and applied to all traffic delivered from it.
 *
 * The COBALT AQM is implemented as a development of the one introduced in
 * CAKE.  Enhancements include a Codel schedule for applying SCE marks and a
 * tighter increment threshold on the BLUE algorithm for handling overload.
 * AQM is applied to the bulk queue only, as a unit rather than per-flow.
 * SCE marking is turned off by default, pending progress in the IETF.
 *
 * As a convenience measure, the deficit-mode shaper from CAKE is also
 * implemented here, albeit without some of its more expensive features.
 * This is a virtual-clock algorithm with packet overhead compensation.
 */

#include <net/pkt_cls.h>
#include <net/tcp.h>

#define LFQ_FLOWS (65536)

struct cobalt_params {
	u64	ce_interval;
	u64	ce_target;
	u64	sce_interval;
	u64	sce_target;
	u64	blue_thresh;
	u64	mtu_time;
	u32	p_inc;
	u32	p_dec;
};

struct cobalt_vars {
	u32	ce_count;
	u32	ce_isqrt;
	ktime_t	ce_next;
	u32	sce_count;
	u32	sce_isqrt;
	ktime_t sce_next;
	ktime_t	blue_timer;
	u32	p_drop;
	bool	ce_dropping;
	bool	ce_marked;
	bool	sce_dropping;
	bool	sce_marked;
};

struct lfq_skb_cb {
	ktime_t enqueue_time;
	u32 flow;
};

struct lfq_queue {
	struct sk_buff *head;
	struct sk_buff *tail;
	struct sk_buff *scan;
	u32 truesize;
};

struct lfq_flow_data {
	s32 deficit;
	u16 backlog;
	bool skip;
	bool dirty;
};

struct lfq_dirty_flows {
	u32 flows[LFQ_FLOWS];
	int len;
};

struct lfq_sched_data {
	/* queues */
	struct lfq_queue sparse;
	struct lfq_queue bulk;

	/* shaper */
	ktime_t	time_next_packet;
	u64	rate_ns;
	u16	rate_shift;
	u16	rate_flags;
	s16	rate_overhead;
	u16	rate_mpu;
	u64	rate_bps;
	struct qdisc_watchdog watchdog;

	/* AQM */
	struct cobalt_params cparams;
	struct cobalt_vars cvars;

	/* resource tracking */
	u32 buffer_limit;

	/* flow tracking */
	struct lfq_flow_data flow_data[LFQ_FLOWS];
	struct lfq_dirty_flows dirty_flows;
	u32	backlog;
};

/* Control Block */

static struct lfq_skb_cb *lfq_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct lfq_skb_cb));
	return (struct lfq_skb_cb *)qdisc_skb_cb(skb)->data;
}

/* Queue */

static struct sk_buff* lfq_push(struct lfq_queue *q, struct sk_buff *skb)
{
	if (!q->head)
		q->head = q->scan = skb;
	else
		q->tail->next = skb;
	skb->prev = q->tail;
	skb->next = NULL;
	q->tail = skb;

	q->truesize += skb->truesize;

	return skb;
}

static struct sk_buff* lfq_pop(struct lfq_queue *q)
{
	struct sk_buff *skb = q->head;

	if (skb) {
		q->head = skb->next;
		if (q->scan == skb)
			q->scan = skb->next;
		if (q->head)
			q->head->prev = NULL;
		else
			q->tail = q->scan = NULL;
		skb_mark_not_on_list(skb);
		q->truesize -= skb->truesize;
	}

	return skb;
}

static struct sk_buff* lfq_pull(struct lfq_queue *q)
{
	struct sk_buff *skb = q->scan;

	if (skb) {
		if (skb->prev)
			skb->prev->next = q->scan = skb->next;
		else
			q->head = q->scan = skb->next;
		if (skb->next)
			skb->next->prev = skb->prev;
		else
			q->tail = skb->prev;
		skb_mark_not_on_list(skb);
		q->truesize -= skb->truesize;
	}

	return skb;
}

static struct sk_buff* lfq_scan_next(struct lfq_queue *q)
{
	return (q->scan = q->scan->next);
}

static struct sk_buff* lfq_scan_head(struct lfq_queue *q)
{
	return (q->scan = q->head);
}

/* COBALT AQM */

#define ISQRT_CACHE (16)
static u32 cobalt_isqrt_cache[ISQRT_CACHE] = {0};

static u64 us_to_ns(u64 us)
{
	return us * NSEC_PER_USEC;
}

static u64 ns_to_us(u64 ns)
{
	return div64_u64(ns, NSEC_PER_USEC);
}

static u64 ms_to_ns(u64 ms)
{
	return ms * NSEC_PER_MSEC;
}

static u32 cobalt_newton_step(u32 count, u32 invsqrt)
{
	u32 invsqrt2;
	u64 val;

	invsqrt2 = ((u64)invsqrt * invsqrt) >> 32;
	val = (3LL << 32) - ((u64)count * invsqrt2);
	val >>= 2;
	val = (val * invsqrt) >> (32 - 2 + 1);

	return (u32) val;
}

static void cobalt_invsqrt(struct cobalt_vars *vars)
{
	vars->ce_isqrt = (vars->ce_count < ISQRT_CACHE) ?
		cobalt_isqrt_cache[vars->ce_count] :
		cobalt_newton_step(vars->ce_count, vars->ce_isqrt);

	vars->sce_isqrt = (vars->sce_count < ISQRT_CACHE) ?
		cobalt_isqrt_cache[vars->sce_count] :
		cobalt_newton_step(vars->sce_count, vars->sce_isqrt);
}

static void cobalt_cache_init(void)
{
	u32 count = 0, isqrt = ~0U;

	cobalt_isqrt_cache[0] = isqrt;

	for (count = 1; count < ISQRT_CACHE; count++) {
		isqrt = cobalt_newton_step(count, isqrt);
		isqrt = cobalt_newton_step(count, isqrt);
		isqrt = cobalt_newton_step(count, isqrt);
		isqrt = cobalt_newton_step(count, isqrt);

		cobalt_isqrt_cache[count] = isqrt;
	}
}

static void cobalt_vars_init(struct cobalt_vars *vars)
{
	memset(vars, 0, sizeof(*vars));

	if (!cobalt_isqrt_cache[0])
		cobalt_cache_init();
}

static ktime_t cobalt_control(ktime_t t, u64 interval, u32 isqrt)
{
	return ktime_add_ns(t, reciprocal_scale(interval, isqrt));
}

static bool cobalt_queue_full(struct cobalt_vars *vars,
			      struct cobalt_params *p,
			      ktime_t now)
{
	bool up = false;

	if (ktime_to_ns(ktime_sub(now, vars->blue_timer)) > p->ce_target) {
		up = !vars->p_drop;
		vars->p_drop += p->p_inc;
		if (vars->p_drop < p->p_inc)
			vars->p_drop = ~0;
		vars->blue_timer = now;
	}

	vars->ce_dropping = true;
	vars->ce_next = now;
	if (!vars->ce_count)
		vars->ce_count = 1;

	if(p->sce_interval) {
		vars->sce_dropping = true;
		vars->sce_next = now;
		if (!vars->sce_count)
			vars->sce_count = 1;
	}

	return up;
}

static bool cobalt_queue_empty(struct cobalt_vars *vars,
			       struct cobalt_params *p,
			       ktime_t now)
{
	bool down = false;

	if (vars->p_drop &&
	    ktime_to_ns(ktime_sub(now, vars->blue_timer)) > p->ce_target) {
		if (vars->p_drop < p->p_dec)
			vars->p_drop = 0;
		else
			vars->p_drop -= p->p_dec;
		vars->blue_timer = now;
		down = !vars->p_drop;
	}
	vars->ce_dropping = false;
	vars->sce_dropping = false;

	while (vars->ce_count && ktime_sub(now, vars->ce_next) >= 0) {
		vars->ce_count--;
		cobalt_invsqrt(vars);
		vars->ce_next = cobalt_control(vars->ce_next,
						 p->ce_interval,
						 vars->ce_isqrt);
	}

	while (vars->sce_count && ktime_sub(now, vars->sce_next) >= 0) {
		vars->sce_count--;
		cobalt_invsqrt(vars);
		vars->sce_next = cobalt_control(vars->sce_next,
						 p->sce_interval,
						 vars->sce_isqrt);
	}

	return down;
}

static bool cobalt_should_drop(struct cobalt_vars *vars,
			       struct cobalt_params *p,
			       ktime_t now,
			       struct sk_buff *skb,
				   ktime_t enqueue_time)
{
	bool next_due, over_target, drop = false;
	ktime_t schedule;
	u64 sojourn = ktime_to_ns(ktime_sub(now, enqueue_time));

	/* Handle SCE marking, but only if enabled */
	vars->sce_marked = false;
	schedule = ktime_sub(now, vars->sce_next);
	over_target =	p->sce_interval &&
			sojourn > p->sce_target &&
			sojourn > p->mtu_time * 2;
	next_due = vars->sce_count && schedule >= 0;

	if (over_target) {
		if (!vars->sce_dropping) {
			vars->sce_dropping = true;
			vars->sce_next = cobalt_control(now, p->sce_interval, vars->sce_isqrt);
		}
		if(!vars->sce_count)
			vars->sce_count = 1;
	} else if (vars->sce_dropping) {
		vars->sce_dropping = false;
	}

	if (next_due && vars->sce_dropping) {
		vars->sce_marked = INET_ECN_set_sce(skb);
		if(vars->sce_marked) {
			vars->sce_count++;
			if (!vars->sce_count)
				vars->sce_count--;
			cobalt_invsqrt(vars);
			vars->sce_next = cobalt_control(vars->sce_next, p->sce_interval, vars->sce_isqrt);
		}
	} else while (next_due) {
		vars->sce_count--;
		cobalt_invsqrt(vars);
		vars->sce_next = cobalt_control(vars->sce_next, p->sce_interval, vars->sce_isqrt);
		schedule = ktime_sub(now, vars->sce_next);
		next_due = vars->sce_count && schedule >= 0;
	}

	/* Handle CE marking */
	vars->ce_marked = false;
	schedule = ktime_sub(now, vars->ce_next);
	over_target =	sojourn > p->ce_target &&
			sojourn > p->mtu_time * 4;
	next_due = vars->ce_count && schedule >= 0;

	if (over_target) {
		if (!vars->ce_dropping) {
			vars->ce_dropping = true;
			vars->ce_next = cobalt_control(now, p->ce_interval, vars->ce_isqrt);
		}
		if(!vars->ce_count)
			vars->ce_count = 1;
	} else if (vars->ce_dropping) {
		vars->ce_dropping = false;
	}

	if (next_due && vars->ce_dropping) {
		drop = !(vars->ce_marked = INET_ECN_set_ce(skb));
		vars->ce_count++;
		if (!vars->ce_count)
			vars->ce_count--;
		cobalt_invsqrt(vars);
		vars->ce_next = cobalt_control(vars->ce_next, p->ce_interval, vars->ce_isqrt);
		schedule = ktime_sub(now, vars->ce_next);
	} else while (next_due) {
		vars->ce_count--;
		cobalt_invsqrt(vars);
		vars->ce_next = cobalt_control(vars->ce_next, p->ce_interval, vars->ce_isqrt);
		schedule = ktime_sub(now, vars->ce_next);
		next_due = vars->ce_count && schedule >= 0;
	}

	/* Handle BLUE */
	if (sojourn > p->blue_thresh)
		cobalt_queue_full(vars, p, now);
	if (vars->p_drop)
		drop |= (prandom_u32() < vars->p_drop);

	/* Activity timeout */
	if (!vars->ce_count)
		vars->ce_next = ktime_add_ns(now, p->ce_interval);
	else if (schedule > 0 && !drop)
		vars->ce_next = now;

	return drop;
}


/* Deficit-mode Shaper */
#define LFQ_FLAG_OVERHEAD (0x01)
#define LFQ_FLAG_ATM      (0x10)
#define LFQ_FLAG_PTM      (0x20)

static u32 lfq_calc_overhead(struct lfq_sched_data *q, u32 len, u32 off)
{
	if (q->rate_flags & LFQ_FLAG_OVERHEAD)
		len -= off;
	len += q->rate_overhead;
	if (len < q->rate_mpu)
		len = q->rate_mpu;

	if (q->rate_flags & LFQ_FLAG_ATM) {
		len += 47;
		len /= 48;
		len *= 53;
	} else if (q->rate_flags & LFQ_FLAG_PTM) {
		len += (len + 63) / 64;
	}
	return len;
}

static u32 lfq_overhead(struct lfq_sched_data *q, const struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int hdr_len, last_len = 0;
	u32 off = skb_network_offset(skb);
	u32 len = qdisc_pkt_len(skb);
	u16 segs = 1;

	if (!shinfo->gso_size)
		return lfq_calc_overhead(q, len, off);

	/* borrowed from qdisc_pkt_len_init() */
	hdr_len = skb_transport_header(skb) - skb_mac_header(skb);

	/* + transport layer */
	if (likely(shinfo->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))) {
		const struct tcphdr *th;
		struct tcphdr _tcphdr;

		th = skb_header_pointer(skb, skb_transport_offset(skb),
		sizeof(_tcphdr), &_tcphdr);
		if (likely(th))
			hdr_len += __tcp_hdrlen(th);
	} else {
		struct udphdr _udphdr;

		if (skb_header_pointer(skb, skb_transport_offset(skb),
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

	return (lfq_calc_overhead(q, len, off) * (segs - 1) +
		lfq_calc_overhead(q, last_len, off));
}

static int lfq_advance_shaper(struct lfq_sched_data *q,
			      struct sk_buff *skb,
			      ktime_t now)
{
	u32 len = lfq_overhead(q, skb);

	if (q->rate_ns) {
		u64 global_dur = (len * q->rate_ns) >> q->rate_shift;

		q->time_next_packet = ktime_add_ns(q->time_next_packet,
						   global_dur);
	}
	return len;
}

static void lfq_unstale_shaper(struct lfq_sched_data *q, ktime_t now)
{
	if (!q->backlog) {
		if (ktime_before(q->time_next_packet, now))
			q->time_next_packet = now;
		else
			qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
	}
}

/* Flows */

static u32 lfq_hash(const struct sk_buff *skb)
{
	/* Implements only 5-tuple flow hash, without set association */
	u32 h;
	struct flow_keys keys;

	skb_flow_dissect_flow_keys(skb, &keys,
				   FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
	h = flow_hash_from_keys(&keys);

	return h % LFQ_FLOWS;
}

static void lfq_set_dirty(struct lfq_sched_data *q, u32 flow)
{
	struct lfq_flow_data *d = &q->flow_data[flow];

	if (!d->dirty) {
		struct lfq_dirty_flows *r = &q->dirty_flows;

		r->flows[r->len++] = flow;
		d->dirty = true;
	}
}

static struct sk_buff* lfq_sweep(struct lfq_sched_data *q)
{
	struct lfq_dirty_flows *r = &q->dirty_flows;
	struct lfq_flow_data *d;
	int i;

	for (i = 0; i < r->len; i++) {
		d = &q->flow_data[r->flows[i]];
		if (!d->skip) {
			if (!d->backlog)
				d->deficit = 0;
		} else {
			d->skip = false;
		}
		d->dirty = false;
	}

	r->len = 0;

	return lfq_scan_head(&q->bulk);
}

/* Core */

static s32 lfq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct lfq_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get();
	u32 len = qdisc_pkt_len(skb);
	u32 flow;
	struct lfq_flow_data *d;
	struct lfq_skb_cb *cb;

	/* GSO splitting */
	if (skb_is_gso(skb)) {
		struct sk_buff *segs, *nskb;
		netdev_features_t features = netif_skb_features(skb);
		unsigned int slen = 0, numsegs = 0;

		segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);
		if (IS_ERR_OR_NULL(segs))
			return qdisc_drop(skb, sch, to_free);

		while(segs) {
			nskb = segs->next;
			skb_mark_not_on_list(segs);

			qdisc_skb_cb(segs)->pkt_len = segs->len;
			slen += segs->len;
			numsegs++;

			lfq_enqueue(segs, sch, to_free);
			segs = nskb;
		}

		qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen);
		consume_skb(skb);

		return NET_XMIT_SUCCESS;
	}

	flow = lfq_hash(skb);
	if (q->buffer_limit) {
		while (q->sparse.truesize + q->bulk.truesize + skb->truesize > q->buffer_limit) {
			if (!(skb = lfq_pop(&q->bulk)))
				skb = lfq_pop(&q->sparse);
			flow = lfq_hash(skb);
			q->flow_data[flow].backlog--;
			lfq_set_dirty(q, flow);
		}
	}

	cb = lfq_cb(skb);
	cb->flow = flow;
	cb->enqueue_time = now;
	d = &q->flow_data[flow];

	if (d->backlog == 0 && d->deficit >= 0 && !d->skip)
		lfq_push(&q->sparse, skb);
	else
		lfq_push(&q->bulk, skb);

	lfq_unstale_shaper(q, now);

	sch->q.qlen++;
	d->backlog++;
	q->backlog += len;
	lfq_set_dirty(q, flow);

	return NET_XMIT_SUCCESS;
}

static void lfq_send(struct Qdisc *sch, struct sk_buff *skb)
{
	struct lfq_sched_data *q = qdisc_priv(sch);
	struct lfq_flow_data *d;
	u32 len = qdisc_pkt_len(skb);

	qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
	d = &q->flow_data[lfq_cb(skb)->flow];
	d->backlog--;
	d->deficit -= len;
	if (d->deficit < 0) {
		d->skip = true;
		d->deficit += psched_mtu(qdisc_dev(sch));
	}
	sch->q.qlen--;
	q->backlog -= len;
	lfq_set_dirty(q, lfq_cb(skb)->flow);
}

static struct sk_buff* lfq_dequeue(struct Qdisc *sch)
{
	struct lfq_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get();
	struct sk_buff *skb;
	struct lfq_flow_data *d;

	if (!sch->q.qlen)
		return NULL;

	/* shaper */
	if (ktime_after(q->time_next_packet, now)) {
		sch->qstats.overlimits++;
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
		return NULL;
	}

	if (!!(skb = lfq_pop(&q->sparse))) {
		lfq_send(sch, skb);
	} else {
		while (q->bulk.head) {
			if (!(skb = q->bulk.scan))
				skb = lfq_sweep(q);

			d = &q->flow_data[lfq_cb(skb)->flow];
			if (!d->skip) {
				lfq_send(sch, skb);
				lfq_pull(&q->bulk);
				break;
			}

			lfq_scan_next(&q->bulk);
		}
	}

	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	/* AQM */
	if (!q->backlog) {
		cobalt_queue_empty(&q->cvars, &q->cparams, now);
	} else if (cobalt_should_drop(&q->cvars, &q->cparams, now, skb,
				lfq_cb(skb)->enqueue_time)) {
		/* drop packet, and try again with the next one */
		qdisc_tree_reduce_backlog(sch, 1, qdisc_pkt_len(skb));
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return lfq_dequeue(sch);
	}
	qdisc_bstats_update(sch, skb);

	/* shaper again */
	lfq_advance_shaper(q, skb, now);
	if (ktime_after(q->time_next_packet, now) && sch->q.qlen)
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);

	return skb;
}

/* Configuration */

static const struct nla_policy lfq_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_BASE_RATE64]   = { .type = NLA_U64 },
	[TCA_CAKE_ATM]		 = { .type = NLA_U32 },
	[TCA_CAKE_OVERHEAD]      = { .type = NLA_S32 },
	[TCA_CAKE_RAW]		 = { .type = NLA_U32 },
	[TCA_CAKE_MPU]		 = { .type = NLA_U32 },
	[TCA_CAKE_RTT]		 = { .type = NLA_U32 },
	[TCA_CAKE_TARGET]	 = { .type = NLA_U32 },
	[TCA_CAKE_MEMORY]	 = { .type = NLA_U32 },
	[TCA_CAKE_SCE]		 = { .type = NLA_U32 },
};

static int lfq_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct lfq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_CAKE_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, lfq_policy, extack);
	if (err < 0)
		return err;

	if (tb[TCA_CAKE_BASE_RATE64])
		q->rate_bps = nla_get_u64(tb[TCA_CAKE_BASE_RATE64]);

	if (tb[TCA_CAKE_ATM]) {
		q->rate_flags &= ~(LFQ_FLAG_ATM | LFQ_FLAG_PTM);
		switch(nla_get_u32(tb[TCA_CAKE_ATM])) {
		case CAKE_ATM_ATM:
			q->rate_flags |= LFQ_FLAG_ATM;
			break;

		case CAKE_ATM_PTM:
			q->rate_flags |= LFQ_FLAG_PTM;
			break;

		default:;
		};
	}

	if (tb[TCA_CAKE_OVERHEAD]) {
		q->rate_overhead = nla_get_s32(tb[TCA_CAKE_OVERHEAD]);
		q->rate_flags |= LFQ_FLAG_OVERHEAD;
	}

	if (tb[TCA_CAKE_RAW])
		q->rate_flags &= ~LFQ_FLAG_OVERHEAD;

	if (tb[TCA_CAKE_MPU])
		q->rate_mpu = nla_get_u32(tb[TCA_CAKE_MPU]);

	if (tb[TCA_CAKE_RTT]) {
		q->cparams.ce_interval = us_to_ns(nla_get_u32(tb[TCA_CAKE_RTT]));

		if (!q->cparams.ce_interval)
			q->cparams.ce_interval = 1;

		q->cparams.blue_thresh = q->cparams.ce_interval * 4;
	}

	if (tb[TCA_CAKE_TARGET]) {
		q->cparams.ce_target = us_to_ns(nla_get_u32(tb[TCA_CAKE_TARGET]));

		if (!q->cparams.ce_target)
			q->cparams.ce_target = 1;

		q->cparams.sce_target = (q->cparams.ce_target+1)/2;
	}

	if (tb[TCA_CAKE_MEMORY])
		q->buffer_limit = nla_get_u32(tb[TCA_CAKE_MEMORY]);

	if (tb[TCA_CAKE_SCE]) {
		u32 sce = nla_get_u32(tb[TCA_CAKE_SCE]);
		if(sce) {
			q->cparams.sce_interval = div64_u64(q->cparams.ce_interval, sce);
			if(!q->cparams.sce_interval)
				q->cparams.sce_interval = 1;
		} else {
			q->cparams.sce_interval = 0;
		}
	}

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

static int lfq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct lfq_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u64_64bit(skb, TCA_CAKE_BASE_RATE64, q->rate_bps,
			      TCA_CAKE_PAD))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_RTT, ns_to_us(q->cparams.ce_interval)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_TARGET, ns_to_us(q->cparams.ce_target)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_OVERHEAD, q->rate_overhead))
		goto nla_put_failure;

	if (!(q->rate_flags & LFQ_FLAG_OVERHEAD))
		if (nla_put_u32(skb, TCA_CAKE_RAW, 0))
			goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_ATM,
	                q->rate_flags & LFQ_FLAG_ATM ? CAKE_ATM_ATM :
	                q->rate_flags & LFQ_FLAG_PTM ? CAKE_ATM_PTM :
	                0))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_MPU, q->rate_mpu))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_MEMORY, q->buffer_limit))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_SCE, q->cparams.sce_interval ?
	                div64_u64(q->cparams.ce_interval, q->cparams.sce_interval)
	                : 0))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int lfq_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct lfq_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	cobalt_vars_init(&q->cvars);
	sch->limit = 10240;

	q->cparams.ce_interval  = ms_to_ns( 100);
	q->cparams.sce_interval =             0 ;  /* off by default, otherwise: 25ms */
	q->cparams.ce_target    = ms_to_ns(   5);
	q->cparams.sce_target   = us_to_ns(2500);
	q->cparams.blue_thresh  = ms_to_ns( 400);
	q->cparams.p_inc	= 1 << 24;
	q->cparams.p_dec	= 1 << 20;

	qdisc_watchdog_init(&q->watchdog, sch);

	if (opt) {
		int err = lfq_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static void lfq_reset(struct Qdisc *sch)
{
	struct lfq_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	while (!!(skb = lfq_pop(&q->sparse)))
		kfree_skb(skb);
	while (!!(skb = lfq_pop(&q->bulk)))
		kfree_skb(skb);
	sch->q.qlen = 0;
	q->backlog = 0;
	memset(&q->flow_data, 0, LFQ_FLOWS * sizeof(struct lfq_flow_data));
	memset(&q->dirty_flows, 0, sizeof(struct lfq_dirty_flows));
}

static void lfq_destroy(struct Qdisc *sch)
{
	struct lfq_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
}


static struct Qdisc_ops lfq_qdisc_ops __read_mostly = {
	.id		=	"lfq_cobalt",
	.priv_size	=	sizeof(struct lfq_sched_data),
	.enqueue	=	lfq_enqueue,
	.dequeue	=	lfq_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.change		=	lfq_change,
	.dump		=	lfq_dump,
	.init		=	lfq_init,
	.reset		=	lfq_reset,
	.destroy	=	lfq_destroy,
	.owner		=	THIS_MODULE,
};

static int __init lfq_module_init(void)
{
	return register_qdisc(&lfq_qdisc_ops);
}

static void __exit lfq_module_exit(void)
{
	unregister_qdisc(&lfq_qdisc_ops);
}

module_init(lfq_module_init)
module_exit(lfq_module_exit)
MODULE_AUTHOR("Jonathon Morton");
MODULE_AUTHOR("Pete Heist");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Lightweight Fair Queueing with COBALT.");
