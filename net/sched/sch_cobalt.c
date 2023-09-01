// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* COBALT AQM discipline
 *
 * Copyright (C) 2022 Jonathan Morton <chromatix99@gmail.com>
 *
 * The COBALT AQM is implemented as a development of the one introduced in
 * CAKE.  Enhancements include a Codel schedule for applying SCE marks and a
 * tighter increment threshold on the BLUE algorithm for handling overload.
 * AQM is applied to the bulk queue only, as a unit rather than per-flow.
 * SCE marking is turned off by default, pending progress in the IETF.
 *
 * This qdisc implements a single queue with no built-in shaper, so that it
 * can be compared directly against simple AQMs like CoDel and PIE.
 */

#include <net/pkt_cls.h>
#include <net/gso.h>
#include <net/tcp.h>

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

struct cobalt_skb_cb {
	ktime_t	enqueue_time;
};

struct cobalt_sched_data {
	/* queues */
	struct sk_buff	*bulk_head;
	struct sk_buff	*bulk_tail;

	/* AQM */
	struct cobalt_params	cparams;
	struct cobalt_vars	cvars;

	/* resource tracking */
	u32	backlog;
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

static struct cobalt_skb_cb *get_cobalt_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct cobalt_skb_cb));
	return (struct cobalt_skb_cb *)qdisc_skb_cb(skb)->data;
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
		vars->sce_next = cobalt_control(now, p->sce_interval, vars->sce_isqrt);
		vars->sce_dropping = false;
	}

	return down;
}

static bool cobalt_should_drop(struct cobalt_vars *vars,
			       struct cobalt_params *p,
			       ktime_t now,
			       struct sk_buff *skb)
{
	bool next_due, over_target, drop = false;
	ktime_t schedule;
	u64 sojourn = ktime_to_ns(ktime_sub(now, cobalt_get_enqueue_time(skb)));

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
			next_due = false;
		}
		if(!vars->sce_count)
			vars->sce_count = 1;
	} else if (vars->sce_dropping) {
		vars->sce_next = cobalt_control(now, p->sce_interval, vars->sce_isqrt);
		vars->sce_dropping = false;
	}

	if (next_due && vars->sce_dropping) {
		vars->sce_marked = INET_ECN_set_ect1(skb);
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
	if (sojourn > p->blue_thresh)
		cobalt_queue_full(vars, p, now);
	if (vars->p_drop)
		drop |= (get_random_u32() < vars->p_drop);

	/* Activity timeout */
	if (!vars->ce_count)
		vars->ce_next = ktime_add_ns(now, p->ce_interval);
	else if (schedule > 0 && !drop)
		vars->ce_next = now;

	return drop;
}


static struct sk_buff* dequeue_bulk(struct cobalt_sched_data *q)
{
	struct sk_buff *skb = q->bulk_head;

	if(skb) {
		q->bulk_head = skb->next;
		skb_mark_not_on_list(skb);
	}

	return skb;
}

static void enqueue_bulk(struct cobalt_sched_data *q, struct sk_buff *skb)
{
	if (!q->bulk_head)
		q->bulk_head = skb;
	else
		q->bulk_tail->next = skb;
	q->bulk_tail = skb;
	skb->next = NULL;
}


/* Core */

static s32 cobalt_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct cobalt_sched_data *q = qdisc_priv(sch);
	int len = qdisc_pkt_len(skb);
	ktime_t now = ktime_get();

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

			cobalt_enqueue(segs, sch, to_free);
		}

		qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen);
		consume_skb(skb);

		return NET_XMIT_SUCCESS;
	}

	/* prepare and enqueue */
	cobalt_set_enqueue_time(skb, now);

	enqueue_bulk(q, skb);

	sch->q.qlen++;
	q->backlog += len;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* cobalt_dequeue(struct Qdisc *sch)
{
	struct cobalt_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get();
	struct sk_buff *skb;
	u32 len;

	if(!sch->q.qlen)
		return NULL;

	skb = dequeue_bulk(q);
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	sch->q.qlen--;
	q->backlog -= (len = qdisc_pkt_len(skb));

	/* AQM */
	if (!q->backlog) {
		cobalt_queue_empty(&q->cvars, &q->cparams, now);
	} else if (cobalt_should_drop(&q->cvars, &q->cparams, now, skb)) {
		/* drop packet, and try again with the next one */
		qdisc_tree_reduce_backlog(sch, 1, len);
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return cobalt_dequeue(sch);
	}
	qdisc_bstats_update(sch, skb);

	return skb;
}


/* Configuration */

static const struct nla_policy cobalt_policy[TCA_CAKE_MAX + 1] = {
	[TCA_CAKE_RTT]		 = { .type = NLA_U32 },
	[TCA_CAKE_TARGET]	 = { .type = NLA_U32 },
	[TCA_CAKE_SCE]		 = { .type = NLA_U32 },
};

static int cobalt_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct cobalt_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_CAKE_MAX + 1];
	int err;

	err = nla_parse_nested(tb, TCA_CAKE_MAX, opt, cobalt_policy, extack);
	if (err < 0)
		return err;

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

	/* unlimited mode */
	sch->flags |= TCQ_F_CAN_BYPASS;

	return 0;
}

static int cobalt_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct cobalt_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_RTT, ns_to_us(q->cparams.ce_interval)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_TARGET, ns_to_us(q->cparams.ce_target)))
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_CAKE_SCE, q->cparams.sce_interval ?
	                div64_u64(q->cparams.ce_interval, q->cparams.sce_interval)
	                : 0))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int cobalt_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct cobalt_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	cobalt_vars_init(&q->cvars);
	sch->limit = 10240;

	q->cparams.ce_interval  = ms_to_ns( 100);
	q->cparams.sce_interval = ms_to_ns(  25);
	q->cparams.ce_target    = ms_to_ns(   5);
	q->cparams.sce_target   = us_to_ns(2500);
	q->cparams.blue_thresh  = ms_to_ns( 400);
	q->cparams.p_inc	= 1 << 24;
	q->cparams.p_dec	= 1 << 20;

//	q->cparams.sce_interval =             0 ;  /* off by default, otherwise: 25ms */

	if (opt) {
		int err = cobalt_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static void cobalt_reset(struct Qdisc *sch)
{
	struct cobalt_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	while (!!(skb = dequeue_bulk(q)))
		kfree_skb(skb);
	q->backlog = 0;
	sch->q.qlen = 0;
}

static void cobalt_destroy(struct Qdisc *sch)
{
}


static struct Qdisc_ops cobalt_qdisc_ops __read_mostly = {
	.id		=	"cobalt",
	.priv_size	=	sizeof(struct cobalt_sched_data),
	.enqueue	=	cobalt_enqueue,
	.dequeue	=	cobalt_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.change		=	cobalt_change,
	.dump		=	cobalt_dump,
	.init		=	cobalt_init,
	.reset		=	cobalt_reset,
	.destroy	=	cobalt_destroy,
	.owner		=	THIS_MODULE,
};

static int __init cobalt_module_init(void)
{
	return register_qdisc(&cobalt_qdisc_ops);
}

static void __exit cobalt_module_exit(void)
{
	unregister_qdisc(&cobalt_qdisc_ops);
}

module_init(cobalt_module_init)
module_exit(cobalt_module_exit)
MODULE_AUTHOR("Jonathan Morton");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("COBALT AQM.");
