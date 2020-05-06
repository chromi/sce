// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Cheap Nasty Queue with COBALT discipline
 *
 * Copyright (C) 2019 Jonathan Morton <chromatix99@gmail.com>
 *
 * This is a very lightweight form of flow-aware queuing, with a built-in
 * deficit-mode shaper and AQM.  The flow-isolation performance will be
 * somewhat inferior to true FQ algorithms like DRR++ (as used in fq_codel
 * and CAKE), but the implementation complexity and CPU overhead should be
 * considerably lower.  This software implementation is intended to show
 * performance with a view to future hardware implementation.
 *
 * The CNQ algorithm is extremely simple: a count of packets in the queue
 * is maintained for each flow, and packets are prioritised into the
 * "sparse queue" if their flow's counter is zero, and into the "bulk queue"
 * otherwise.  Flows are identified by the traditional 5-tuple.  Overall the
 * enqueue and dequeue operations are O(1).
 *
 * Packets in the sparse queue are accompanied by a dummy
 * packet inserted into the bulk queue, and the counter is only decremented
 * when that dummy packet is dequeued from the bulk queue.  This means that
 * sparse flows are prioritised, with sparseness being defined by the packet
 * arrival rate being at least as long as the sojourn time of the bulk queue.
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

#define CNQ_QUEUES (65536)

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

struct cnq_cobalt_skb_cb {
	ktime_t	enqueue_time;
	u16	flow;
	bool	sparse;
};

struct cnq_class_data {
	/* queues */
	struct sk_buff	*sprs_head;
	struct sk_buff	*sprs_tail;
	struct sk_buff	*bulk_head;
	struct sk_buff	*bulk_tail;

	/* resource tracking */
	u32 active_flows;
	u32 active_sparse;
	u32 sparse_dummies;
	u32	backlog;
	s32 deficit;
	u16	backlogs[CNQ_QUEUES];

	/* AQM */
	struct cobalt_params	cparams;
};

struct cnq_sched_data {
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
	struct cobalt_vars	cvars[CNQ_QUEUES];
	u16	decay_index;

	/* resource tracking */
	struct cnq_class_data classes[2];

	/* Diffserv configuration */
	u8	dscp;
	u8	divisor;
};


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

static struct cnq_cobalt_skb_cb *get_cobalt_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct cnq_cobalt_skb_cb));
	return (struct cnq_cobalt_skb_cb *)qdisc_skb_cb(skb)->data;
}

static ktime_t cobalt_get_enqueue_time(const struct sk_buff *skb)
{
	return get_cobalt_cb(skb)->enqueue_time;
}

static void cobalt_set_enqueue_time(struct sk_buff *skb,
				    ktime_t now)
{
	get_cobalt_cb(skb)->enqueue_time = now;
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

static ktime_t cobalt_reflect(ktime_t now, ktime_t t, u64 interval, u32 isqrt)
{
	ktime_t then = ktime_sub(ktime_add(now, now), t);
	return ktime_add_ns(then, reciprocal_scale(interval, isqrt));
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

	while (vars->ce_count && ktime_sub(now, vars->ce_next) >= 0) {
		vars->ce_count--;
		cobalt_invsqrt(vars);
		vars->ce_next = cobalt_control(vars->ce_next,
						 p->ce_interval,
						 vars->ce_isqrt);
	}
	if(vars->ce_dropping) {
	/*	vars->ce_next = cobalt_reflect(now, vars->ce_next, p->ce_interval, vars->ce_isqrt); */
		vars->ce_next = cobalt_control(now, p->ce_interval, vars->ce_isqrt);
		vars->ce_dropping = false;
	}

	while (vars->sce_count && ktime_sub(now, vars->sce_next) >= 0) {
		vars->sce_count--;
		cobalt_invsqrt(vars);
		vars->sce_next = cobalt_control(vars->sce_next,
						 p->sce_interval,
						 vars->sce_isqrt);
	}
	if(vars->sce_dropping) {
		vars->sce_next = cobalt_reflect(now, vars->sce_next, p->sce_interval, vars->sce_isqrt);
		vars->sce_dropping = false;
	}

	return down;
}

static bool cobalt_should_drop(struct cobalt_vars *vars,
			       struct cobalt_params *p,
			       ktime_t now,
			       struct sk_buff *skb,
			       u32 flow_backlog,
			       u32 active_flows,
			       u32 total_backlog)
{
	bool next_due, over_target, drop = false;
	ktime_t schedule;
	u64 sojourn = ktime_to_ns(ktime_sub(now, cobalt_get_enqueue_time(skb)));

	/* Weighted sojourn is compared against weighted targets.
	 * This penalises queue occupancy beyond fair share.
	 */
	u64 weighted_sojourn = sojourn * flow_backlog * active_flows;

	/* Handle SCE marking, but only if enabled */
	vars->sce_marked = false;
	schedule = ktime_sub(now, vars->sce_next);
	over_target =	p->sce_interval &&
			weighted_sojourn > p->sce_target * total_backlog &&
			sojourn > p->mtu_time * 2;
	next_due = vars->sce_count && schedule >= 0;

	if (over_target) {
		if (!vars->sce_dropping) {
			vars->sce_dropping = true;
			if (next_due)
				vars->sce_next = cobalt_control(now, p->sce_interval, vars->sce_isqrt);
			else
				vars->sce_next = cobalt_reflect(now, vars->sce_next, p->sce_interval, vars->sce_isqrt);
			next_due = false;
		}
		if(!vars->sce_count)
			vars->sce_count = 1;
	} else if (vars->sce_dropping) {
		if (next_due)
			vars->sce_next = cobalt_control(now, p->sce_interval, vars->sce_isqrt);
		else
			vars->sce_next = cobalt_reflect(now, vars->sce_next, p->sce_interval, vars->sce_isqrt);
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
	over_target =	weighted_sojourn > p->ce_target * total_backlog &&
			sojourn > p->mtu_time * 4;
	next_due = vars->ce_count && schedule >= 0;

	if (over_target) {
		if (!vars->ce_dropping) {
			vars->ce_dropping = true;
			vars->ce_next = cobalt_control(now, p->ce_interval, vars->ce_isqrt);
			next_due = false;
		}
		if(!vars->ce_count)
			vars->ce_count = 1;
	} else if (vars->ce_dropping) {
		vars->ce_next = cobalt_control(now, p->ce_interval, vars->ce_isqrt);
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
	if (weighted_sojourn > p->blue_thresh * total_backlog)
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
#define CNQ_FLAG_OVERHEAD (0x01)
#define CNQ_FLAG_ATM      (0x10)
#define CNQ_FLAG_PTM      (0x20)

static u32 cnq_calc_overhead(struct cnq_sched_data *q, u32 len, u32 off)
{
	if (q->rate_flags & CNQ_FLAG_OVERHEAD)
		len -= off;
	len += q->rate_overhead;
	if (len < q->rate_mpu)
		len = q->rate_mpu;

	if (q->rate_flags & CNQ_FLAG_ATM) {
		len += 47;
		len /= 48;
		len *= 53;
	} else if (q->rate_flags & CNQ_FLAG_PTM) {
		len += (len + 63) / 64;
	}
	return len;
}

static u32 cnq_overhead(struct cnq_sched_data *q, const struct sk_buff *skb)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int hdr_len, last_len = 0;
	u32 off = skb_network_offset(skb);
	u32 len = qdisc_pkt_len(skb);
	u16 segs = 1;

	if (!shinfo->gso_size)
		return cnq_calc_overhead(q, len, off);

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

	return (cnq_calc_overhead(q, len, off) * (segs - 1) +
		cnq_calc_overhead(q, last_len, off));
}

static int cnq_advance_shaper(struct cnq_sched_data *q,
			      struct sk_buff *skb,
			      ktime_t now)
{
	u32 len = cnq_overhead(q, skb);

	if (q->rate_ns) {
		u64 global_dur = (len * q->rate_ns) >> q->rate_shift;

		q->time_next_packet = ktime_add_ns(q->time_next_packet,
						   global_dur);
	}
	return len;
}

static void cnq_unstale_shaper(struct cnq_sched_data *q, ktime_t now)
{
	if (!(q->classes[0].backlog + q->classes[1].backlog)) {
		if (ktime_before(q->time_next_packet, now))
			q->time_next_packet = now;
		else
			qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
	}
}


/* Flows */

static u32 cnq_hash(const struct sk_buff *skb)
{
	/* Implements only 5-tuple flow hash, without set association */
	u32 flow_hash = 0;
	struct flow_keys keys;

	skb_flow_dissect_flow_keys(skb, &keys,
				   FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL);
	flow_hash = flow_hash_from_keys(&keys);

	return flow_hash % CNQ_QUEUES;
}

static struct sk_buff* dequeue_bulk(struct cnq_class_data *cls)
{
	struct sk_buff *skb = cls->bulk_head;

	if(skb) {
		cls->bulk_head = skb->next;
		skb_mark_not_on_list(skb);

		WARN_ON(!cls->backlogs[get_cobalt_cb(skb)->flow]);
		cls->backlogs[get_cobalt_cb(skb)->flow]--;

		if(!cls->backlogs[get_cobalt_cb(skb)->flow]) {
			WARN_ON(!cls->active_flows);
			cls->active_flows--;
		}

		if(get_cobalt_cb(skb)->sparse) {
			/* dummy packet, do not deliver */
			cls->sparse_dummies--;
			kfree_skb(skb);
			return dequeue_bulk(cls);
		}
	}

	return skb;
}

static struct sk_buff* dequeue_sparse(struct cnq_class_data *cls)
{
	struct sk_buff *skb = cls->sprs_head;

	if(skb) {
		cls->sprs_head = skb->next;
		skb_mark_not_on_list(skb);
		cls->active_sparse--;
	}
	return skb;
}

static void enqueue_bulk(struct cnq_class_data *cls, struct sk_buff *skb)
{
	if(!cls->backlogs[get_cobalt_cb(skb)->flow])
		cls->active_flows++;
	cls->backlogs[get_cobalt_cb(skb)->flow]++;

	if (!cls->bulk_head)
		cls->bulk_head = skb;
	else
		cls->bulk_tail->next = skb;
	cls->bulk_tail = skb;
	skb->next = NULL;
}

static void enqueue_sparse(struct cnq_class_data *cls, struct sk_buff *skb)
{
	struct sk_buff *cskb;

	/* In parallel, enqueue a dummy packet into the bulk queue. */
	get_cobalt_cb(skb)->sparse = true;
	cskb = skb_clone(skb, GFP_ATOMIC);
	if (likely(cskb)) {
		enqueue_bulk(cls, cskb);
		cls->sparse_dummies++;
	} else {
		/* allocation failure */
		get_cobalt_cb(skb)->sparse = false;
		enqueue_bulk(cls, skb);
		return;
	}

	if (!cls->sprs_head)
		cls->sprs_head = skb;
	else
		cls->sprs_tail->next = skb;
	cls->sprs_tail = skb;
	skb->next = NULL;

	cls->active_sparse++;
}

static u8 cnq_get_diffserv(struct sk_buff *skb)
{
	int wlen = skb_network_offset(skb);

	switch (tc_skb_protocol(skb)) {
	case htons(ETH_P_IP):
		wlen += sizeof(struct iphdr);
		if (!pskb_may_pull(skb, wlen))
			return 0;
		return ipv4_get_dsfield(ip_hdr(skb)) >> 2;

	case htons(ETH_P_IPV6):
		wlen += sizeof(struct ipv6hdr);
		if (!pskb_may_pull(skb, wlen))
			return 0;
		return ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;

	default:
		return 0;
	};
}


/* Core */

static s32 cnq_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct cnq_sched_data *q = qdisc_priv(sch);
	struct cnq_cobalt_skb_cb *cb = get_cobalt_cb(skb);
	int len = qdisc_pkt_len(skb);
	ktime_t now = ktime_get();
	u32 flow;
	struct cnq_class_data *cls = &q->classes[q->dscp && q->dscp == cnq_get_diffserv(skb)];

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

			cnq_enqueue(segs, sch, to_free);
			segs = nskb;
		}

		qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen);
		consume_skb(skb);

		return NET_XMIT_SUCCESS;
	}

	/* prepare and enqueue */
	cobalt_set_enqueue_time(skb, now);
	cb->flow = flow = cnq_hash(skb);
	cb->sparse = false;

	if(cls->backlogs[flow])
		enqueue_bulk(cls, skb);
	else
		enqueue_sparse(cls, skb);

	cnq_unstale_shaper(q, now);

	sch->q.qlen++;
	cls->backlog += len;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* cnq_dequeue(struct Qdisc *sch)
{
	struct cnq_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get();
	struct sk_buff *skb;
	u32 len;
	u32 flow;
	bool sparse = true;
	struct cnq_class_data *cls = NULL, *other_cls = NULL;
	s32 c = 0;

	if(!sch->q.qlen)
		return NULL;

	/* shaper */
	if (ktime_after(q->time_next_packet, now)) {
		sch->qstats.overlimits++;
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);
		return NULL;
	}

	/* choose class to service */
	if (!q->classes[1].backlog)
		c = 0;
	else if (!q->classes[0].backlog)
		c = 1;
	else
		c = q->classes[0].deficit >= q->classes[1].deficit;
	cls = &q->classes[c];
	other_cls = &q->classes[!c];

	/* update class deficits for flow-fair delivery */
	cls->deficit += other_cls->active_flows + other_cls->active_sparse - other_cls->sparse_dummies;
	c = min(cls->deficit, other_cls->deficit);
	cls->deficit -= c;
	other_cls->deficit -= c;

	/* sparse queue has strict priority */
	skb = dequeue_sparse(cls);
	if (!skb) {
		skb = dequeue_bulk(cls);
		sparse = false;
	}
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	flow = get_cobalt_cb(skb)->flow;
	sch->q.qlen--;
	cls->backlog -= (len = qdisc_pkt_len(skb));

	/* AQM; avoid dropping last packet in queue from this flow */
	if (sparse) {
		cobalt_queue_empty(&q->cvars[flow], &cls->cparams, now);
	} else if (cobalt_should_drop(&q->cvars[flow], &cls->cparams, now, skb,
	                              cls->backlogs[flow]+1,
	                              cls->active_flows - cls->sparse_dummies,
	                              sch->q.qlen+1)
	           && cls->backlogs[flow])
	{
		/* drop packet, and try again with the next one */
		qdisc_tree_reduce_backlog(sch, 1, len);
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return cnq_dequeue(sch);
	}
	qdisc_bstats_update(sch, skb);

	/* shaper again */
	cnq_advance_shaper(q, skb, now);
	if (ktime_after(q->time_next_packet, now) && sch->q.qlen)
		qdisc_watchdog_schedule_ns(&q->watchdog, q->time_next_packet);

	/* decay idle AQMs */
	if(!q->classes[0].backlogs[q->decay_index] && !q->classes[1].backlogs[q->decay_index])
		cobalt_queue_empty(&q->cvars[q->decay_index], &q->classes[0].cparams, now);
	q->decay_index = (q->decay_index + 1) % CNQ_QUEUES;

	/* try to drain the queue of dummy packets */
	for (c = 0; c < 2; c++) {
		cls = &q->classes[c];
		while(cls->sparse_dummies && !cls->active_sparse) {
			struct sk_buff *sskb = cls->bulk_head;
			if(unlikely(!sskb) || likely(!get_cobalt_cb(sskb)->sparse))
				break;

			cls->bulk_head = sskb->next;
			skb_mark_not_on_list(sskb);

			WARN_ON(!cls->backlogs[get_cobalt_cb(sskb)->flow]);
			cls->backlogs[get_cobalt_cb(sskb)->flow]--;

			if(!cls->backlogs[get_cobalt_cb(sskb)->flow]) {
				WARN_ON(!cls->active_flows);
				cls->active_flows--;
			}

			cls->sparse_dummies--;
			kfree_skb(sskb);
		}
	}

	return skb;
}


/* Configuration */

static const struct nla_policy cnq_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_BASE_RATE64]   = { .type = NLA_U64 },
	[TCA_CAKE_ATM]		 = { .type = NLA_U32 },
	[TCA_CAKE_OVERHEAD]      = { .type = NLA_S32 },
	[TCA_CAKE_RAW]		 = { .type = NLA_U32 },
	[TCA_CAKE_MPU]		 = { .type = NLA_U32 },
	[TCA_CAKE_RTT]		 = { .type = NLA_U32 },
	[TCA_CAKE_TARGET]	 = { .type = NLA_U32 },
	[TCA_CAKE_SCE]		 = { .type = NLA_U32 },
};

static int cnq_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct cnq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_CAKE_MAX + 1];
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cnq_policy, extack);
	if (err < 0)
		return err;

	if (tb[TCA_CAKE_BASE_RATE64])
		q->rate_bps = nla_get_u64(tb[TCA_CAKE_BASE_RATE64]);

	if (tb[TCA_CAKE_ATM]) {
		q->rate_flags &= ~(CNQ_FLAG_ATM | CNQ_FLAG_PTM);
		switch(nla_get_u32(tb[TCA_CAKE_ATM])) {
		case CAKE_ATM_ATM:
			q->rate_flags |= CNQ_FLAG_ATM;
			break;

		case CAKE_ATM_PTM:
			q->rate_flags |= CNQ_FLAG_PTM;
			break;

		default:;
		};
	}

	if (tb[TCA_CAKE_OVERHEAD]) {
		q->rate_overhead = nla_get_s32(tb[TCA_CAKE_OVERHEAD]);
		q->rate_flags |= CNQ_FLAG_OVERHEAD;
	}

	if (tb[TCA_CAKE_RAW])
		q->rate_flags &= ~CNQ_FLAG_OVERHEAD;

	if (tb[TCA_CAKE_MPU])
		q->rate_mpu = nla_get_u32(tb[TCA_CAKE_MPU]);

	if (tb[TCA_CAKE_RTT]) {
		q->classes[0].cparams.ce_interval = us_to_ns(nla_get_u32(tb[TCA_CAKE_RTT]));
		q->classes[1].cparams.ce_interval = q->classes[0].cparams.ce_interval / q->divisor;

		if (!q->classes[0].cparams.ce_interval)
			q->classes[0].cparams.ce_interval = 1;
		if (!q->classes[1].cparams.ce_interval)
			q->classes[1].cparams.ce_interval = 1;

		q->classes[0].cparams.blue_thresh = q->classes[0].cparams.ce_interval * 4;
		q->classes[1].cparams.blue_thresh = q->classes[1].cparams.ce_interval * 4;
	}

	if (tb[TCA_CAKE_TARGET]) {
		q->classes[0].cparams.ce_target = us_to_ns(nla_get_u32(tb[TCA_CAKE_TARGET]));
		q->classes[1].cparams.ce_target = q->classes[0].cparams.ce_target / q->divisor;

		if (!q->classes[0].cparams.ce_target)
			q->classes[0].cparams.ce_target = 1;
		if (!q->classes[1].cparams.ce_target)
			q->classes[1].cparams.ce_target = 1;

		q->classes[0].cparams.sce_target = (q->classes[0].cparams.ce_target+1)/2;
		q->classes[1].cparams.sce_target = (q->classes[1].cparams.ce_target+1)/2;
	}

	if (tb[TCA_CAKE_SCE]) {
		u32 sce = nla_get_u32(tb[TCA_CAKE_SCE]);
		if(sce) {
			q->classes[0].cparams.sce_interval = div64_u64(q->classes[0].cparams.ce_interval, sce);
			q->classes[1].cparams.sce_interval = div64_u64(q->classes[1].cparams.ce_interval, sce);

			if (!q->classes[0].cparams.sce_interval)
				q->classes[0].cparams.sce_interval = 1;
			if (!q->classes[1].cparams.sce_interval)
				q->classes[1].cparams.sce_interval = 1;
		} else {
			q->classes[0].cparams.sce_interval = 0;
			q->classes[1].cparams.sce_interval = 0;
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

static int cnq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct cnq_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u64_64bit(skb, TCA_CAKE_BASE_RATE64, q->rate_bps,
			      TCA_CAKE_PAD))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_RTT, ns_to_us(q->classes[0].cparams.ce_interval)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_TARGET, ns_to_us(q->classes[0].cparams.ce_target)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_OVERHEAD, q->rate_overhead))
		goto nla_put_failure;

	if (!(q->rate_flags & CNQ_FLAG_OVERHEAD))
		if (nla_put_u32(skb, TCA_CAKE_RAW, 0))
			goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_ATM,
	                q->rate_flags & CNQ_FLAG_ATM ? CAKE_ATM_ATM :
	                q->rate_flags & CNQ_FLAG_PTM ? CAKE_ATM_PTM :
	                0))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_MPU, q->rate_mpu))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_SCE, q->classes[0].cparams.sce_interval ?
	                div64_u64(q->classes[0].cparams.ce_interval, q->classes[0].cparams.sce_interval)
	                : 0))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int cnq_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct cnq_sched_data *q = qdisc_priv(sch);
	u32 i;

	memset(q, 0, sizeof(*q));
	for(i=0; i < CNQ_QUEUES; i++)
		cobalt_vars_init(&q->cvars[i]);
	sch->limit = 10240;

	q->dscp = 4; /* Legacy minimise-delay codepoint */
	q->divisor = 5;

	q->classes[0].cparams.ce_interval  = ms_to_ns( 100);
	q->classes[0].cparams.sce_interval = ms_to_ns(  25);
	q->classes[0].cparams.ce_target    = ms_to_ns(   5);
	q->classes[0].cparams.sce_target   = us_to_ns(2500);
	q->classes[0].cparams.blue_thresh  = ms_to_ns( 400);
	q->classes[0].cparams.p_inc	= 1 << 24;
	q->classes[0].cparams.p_dec	= 1 << 20;

	q->classes[1].cparams.ce_interval  = ms_to_ns(  20);
	q->classes[1].cparams.sce_interval = ms_to_ns(   5);
	q->classes[1].cparams.ce_target    = ms_to_ns(   1);
	q->classes[1].cparams.sce_target   = us_to_ns( 500);
	q->classes[1].cparams.blue_thresh  = ms_to_ns(  80);
	q->classes[1].cparams.p_inc	= 1 << 24;
	q->classes[1].cparams.p_dec	= 1 << 20;

	qdisc_watchdog_init(&q->watchdog, sch);

	if (opt) {
		int err = cnq_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static void cnq_reset(struct Qdisc *sch)
{
	struct cnq_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	u8 cls;

	for(cls=0; cls < 2; cls++) {
		while (!!(skb = dequeue_sparse(&q->classes[cls])))
			kfree_skb(skb);
		while (!!(skb = dequeue_bulk(&q->classes[cls])))
			kfree_skb(skb);
		q->classes[cls].backlog = 0;
	}
	sch->q.qlen = 0;
}

static void cnq_destroy(struct Qdisc *sch)
{
	struct cnq_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_cancel(&q->watchdog);
}


static struct Qdisc_ops cnq_qdisc_ops __read_mostly = {
	.id		=	"twin_codel_af",
	.priv_size	=	sizeof(struct cnq_sched_data),
	.enqueue	=	cnq_enqueue,
	.dequeue	=	cnq_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.change		=	cnq_change,
	.dump		=	cnq_dump,
	.init		=	cnq_init,
	.reset		=	cnq_reset,
	.destroy	=	cnq_destroy,
	.owner		=	THIS_MODULE,
};

static int __init cnq_module_init(void)
{
	return register_qdisc(&cnq_qdisc_ops);
}

static void __exit cnq_module_exit(void)
{
	unregister_qdisc(&cnq_qdisc_ops);
}

module_init(cnq_module_init)
module_exit(cnq_module_exit)
MODULE_AUTHOR("Jonathan Morton");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Twinned Cheap Nasty Queuing with Codel and Approximate Fairness.");
