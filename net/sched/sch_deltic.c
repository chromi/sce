// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* DelTiC (Delay Time Control) AQM discipline
 *
 * Copyright (C) 2022 Jonathan Morton <chromatix99@gmail.com>
 *
 * DelTiC is a fully time-domain AQM based on a delta-sigma control loop and
 * a numerically-controlled oscillator.  Delta-sigma means a PID controller
 * lacking a Proportional term, with the D term accumulated into the I term.
 *
 * This qdisc implements a single queue with no built-in shaper, so that it
 * can be compared directly against simple AQMs like CoDel and PIE.
 */

#include <net/pkt_cls.h>
#include <net/gso.h>
#include <net/tcp.h>

struct deltic_params {
	u32 frequency_scale;	/* product of sig_freq and resonance */
	u32 target;		/* sojourn time in nanoseconds */
	u16 resonance;	/* target queue depth expressed as a frequency, Hz */
};

struct deltic_vars {
	s64 accumulator;    // for I part of PID controller
	u64 history;        // for D part of PID controller
	ktime_t timestamp;  // time last packet was processed
	u64 oscillator;     // Numerically Controlled Oscillator's accumulator
};

struct deltic_skb_cb {
	ktime_t	enqueue_time;
};

struct deltic_sched_data {
	/* queues */
	struct sk_buff	*bulk_head;
	struct sk_buff	*bulk_tail;

	/* AQM params */
	struct deltic_params	sce_params;
	struct deltic_params	ecn_params;
	struct deltic_params	drp_params;
	u16	sig_freq;

	/* AQM state */
	struct deltic_vars	sce_vars;
	struct deltic_vars	ecn_vars;
	struct deltic_vars	drp_vars;

	/* resource tracking */
	u32	backlog;
};


/* DelTiC AQM */
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

static struct deltic_skb_cb *get_deltic_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct deltic_skb_cb));
	return (struct deltic_skb_cb *)qdisc_skb_cb(skb)->data;
}

static ktime_t deltic_get_enqueue_time(const struct sk_buff *skb)
{
	return get_deltic_cb(skb)->enqueue_time;
}

static void deltic_set_enqueue_time(struct sk_buff *skb,
				    ktime_t now)
{
	get_deltic_cb(skb)->enqueue_time = now;
}

static bool deltic_control(struct deltic_vars *vars,
			       struct deltic_params *p,
			       ktime_t now,
			       struct sk_buff *skb)
{
	// Delta-Sigma control is essentially a PID controller without the P term:

	// slope = (sojourn - last_sojourn) / (now - then)
	// acc = max(0, acc + (slope + sojourn - target) * (now - then) * resonant_freq)

	// The above simplifies by cancelling the division in slope calculation
	// against the multiplication by the same quantity:

	// acc = max(0, acc + (sojourn - last_sojourn) + (sojourn - target) * (now - then) * resonant_freq)

	// Since we still multiply two fixed-point values (times in nanoseconds), we need to
	// correct that before adding the result to other time values.  Our helper function
	// ns_scaled_mul() does that for us.  There are some other fixed-point oddities which
	// we also need to take care of.

	bool mark = false;
	u64 sojourn = ktime_to_ns(ktime_sub(now, deltic_get_enqueue_time(skb)));
	u64 interval = ktime_to_ns(ktime_sub(now, vars->timestamp));

	if(interval > NSEC_PER_SEC) {
		// Avoid overflow risks when coming out of idle
		if(sojourn < p->target) {
			interval = 0;
			vars->accumulator = 0;
		} else {
			interval = NSEC_PER_SEC;
		}
	}

	{
		s64 delta = sojourn - vars->history;
		s64 sigma = ns_scaled_mul(sojourn - p->target, interval) * p->resonance;

		vars->accumulator += delta + sigma;
		if(vars->accumulator < 0) {
			vars->accumulator = 0;
			vars->oscillator  = 0;
		}

		vars->history = sojourn;
		vars->timestamp = now;
	}

	// Suppress marking below half of control target
	if(sojourn * 2 >= p->target) {
		// Numerically Controlled Oscillator:
		// osc += acc * (now - then) * frequency_scale
		// Issue a mark event when osc overflows.

		vars->oscillator += ns_scaled_mul(vars->accumulator, interval) * p->frequency_scale;
		if(vars->oscillator >= NSEC_PER_SEC) {
			mark = true;
			vars->oscillator -= NSEC_PER_SEC;
		}

		// Soft limit on over-controlling
		if(vars->oscillator > NSEC_PER_SEC)
			vars->accumulator -= vars->accumulator >> 4;
	}

	return mark;
}


static struct sk_buff* dequeue_bulk(struct deltic_sched_data *q)
{
	struct sk_buff *skb = q->bulk_head;

	if(skb) {
		q->bulk_head = skb->next;
		skb_mark_not_on_list(skb);
	}

	return skb;
}

static void enqueue_bulk(struct deltic_sched_data *q, struct sk_buff *skb)
{
	if (!q->bulk_head)
		q->bulk_head = skb;
	else
		q->bulk_tail->next = skb;
	q->bulk_tail = skb;
	skb->next = NULL;
}


/* Core */

static s32 deltic_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	struct deltic_sched_data *q = qdisc_priv(sch);
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

			deltic_enqueue(segs, sch, to_free);
		}

		qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen);
		consume_skb(skb);

		return NET_XMIT_SUCCESS;
	}

	/* prepare and enqueue */
	deltic_set_enqueue_time(skb, now);

	enqueue_bulk(q, skb);

	sch->q.qlen++;
	q->backlog += len;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* deltic_dequeue(struct Qdisc *sch)
{
	struct deltic_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get();
	struct sk_buff *skb;
	u32 len;
	bool mark_sce, mark_ecn, drop;

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
	mark_sce = q->sce_params.resonance && deltic_control(&q->sce_vars, &q->sce_params, now, skb);
	mark_ecn = q->ecn_params.resonance && deltic_control(&q->ecn_vars, &q->ecn_params, now, skb);
	drop     = q->drp_params.resonance && deltic_control(&q->drp_vars, &q->drp_params, now, skb);

	if(mark_sce)
		INET_ECN_set_ect1(skb);

	if(mark_ecn)
		if(!INET_ECN_set_ce(skb))
			drop = true;

	/* We can't call qdisc_tree_reduce_backlog() if our qlen is 0 or HTB crashes.
	 * Defer it for the next round.
	 */
	if (drop && sch->q.qlen) {
		/* drop packet, and try again with the next one */
		qdisc_tree_reduce_backlog(sch, 1, len);
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return deltic_dequeue(sch);
	}
	qdisc_bstats_update(sch, skb);

	return skb;
}


/* Configuration */

static const struct nla_policy deltic_policy[TCA_DELTIC_MAX + 1] = {
	[TCA_DELTIC_FREQ_DROP]   	= { .type = NLA_U16 },  // resonance frequency for drop controller
	[TCA_DELTIC_FREQ_ECN]   	= { .type = NLA_U16 },  // resonance frequency for ECN controller
	[TCA_DELTIC_FREQ_SCE]   	= { .type = NLA_U16 },  // resonance frequency for SCE controller
	[TCA_DELTIC_FREQ_SIGNAL]	= { .type = NLA_U16 },  // baseline signalling frequency for all controllers
};

static void deltic_parameterise(struct deltic_params *p, const u16 res_freq, const u16 sig_freq)
{
	p->resonance = res_freq;

	if(res_freq && sig_freq) {
		p->target = NSEC_PER_SEC / res_freq;
		p->frequency_scale = res_freq * sig_freq;
	} else {
		p->target = NSEC_PER_SEC;
		p->frequency_scale = 0;
	}
}

static int deltic_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct deltic_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_DELTIC_MAX + 1];
	int err;

	err = nla_parse_nested(tb, TCA_DELTIC_MAX, opt, deltic_policy, extack);
	if (err < 0)
		return err;

	if (tb[TCA_DELTIC_FREQ_SIGNAL])
		q->sig_freq = nla_get_u16(tb[TCA_DELTIC_FREQ_SIGNAL]);

	if (tb[TCA_DELTIC_FREQ_DROP])
		deltic_parameterise(&q->drp_params, nla_get_u16(tb[TCA_DELTIC_FREQ_DROP]), q->sig_freq);

	if (tb[TCA_DELTIC_FREQ_ECN])
		deltic_parameterise(&q->ecn_params, nla_get_u16(tb[TCA_DELTIC_FREQ_ECN]), q->sig_freq);

	if (tb[TCA_DELTIC_FREQ_SCE])
		deltic_parameterise(&q->sce_params, nla_get_u16(tb[TCA_DELTIC_FREQ_SCE]), q->sig_freq);

	/* unlimited mode */
	sch->flags |= TCQ_F_CAN_BYPASS;

	return 0;
}

static int deltic_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct deltic_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (!opts)
		goto nla_put_failure;

	if (nla_put_u16(skb, TCA_DELTIC_FREQ_SIGNAL, q->sig_freq))
		goto nla_put_failure;

	if (nla_put_u16(skb, TCA_DELTIC_FREQ_DROP, q->drp_params.resonance))
		goto nla_put_failure;

	if (nla_put_u16(skb, TCA_DELTIC_FREQ_ECN, q->ecn_params.resonance))
		goto nla_put_failure;

	if (nla_put_u16(skb, TCA_DELTIC_FREQ_SCE, q->sce_params.resonance))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	return -1;
}

static int deltic_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct deltic_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	sch->limit = 10240;

	q->sig_freq = 12;	// signalling rate when accumulator == target is 12Hz
	deltic_parameterise(&q->drp_params,   8, q->sig_freq);  // 125ms target for hard dropping
	deltic_parameterise(&q->ecn_params,  40, q->sig_freq);  //  25ms target for ECN marking
	deltic_parameterise(&q->sce_params, 200, q->sig_freq);  //   5ms target for SCE marking

//	deltic_parameterise(&q->sce_params,   0);  //  default disable SCE marking

	if (opt) {
		int err = deltic_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static void deltic_reset(struct Qdisc *sch)
{
	struct deltic_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	while (!!(skb = dequeue_bulk(q)))
		kfree_skb(skb);
	q->backlog = 0;
	sch->q.qlen = 0;
}

static void deltic_destroy(struct Qdisc *sch)
{
}


static struct Qdisc_ops deltic_qdisc_ops __read_mostly = {
	.id		=	"deltic",
	.priv_size	=	sizeof(struct deltic_sched_data),
	.enqueue	=	deltic_enqueue,
	.dequeue	=	deltic_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.change		=	deltic_change,
	.dump		=	deltic_dump,
	.init		=	deltic_init,
	.reset		=	deltic_reset,
	.destroy	=	deltic_destroy,
	.owner		=	THIS_MODULE,
};

static int __init deltic_module_init(void)
{
	return register_qdisc(&deltic_qdisc_ops);
}

static void __exit deltic_module_exit(void)
{
	unregister_qdisc(&deltic_qdisc_ops);
}

module_init(deltic_module_init)
module_exit(deltic_module_exit)
MODULE_AUTHOR("Jonathan Morton");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Delay Time Control (DelTiC) AQM.");
