// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* DelTiC (Delay Time Control) AQM discipline
 *
 * Copyright (C) 2022-4 Jonathan Morton <chromatix99@gmail.com>
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

#include <net/deltic.h>

#define FREQ_SHIFT (16)

struct deltic_sched_data {
	/* queues */
	struct sk_buff	*bulk_head;
	struct sk_buff	*bulk_tail;

	/* AQM params */
	struct deltic_params	sce_params;
	struct deltic_params	ecn_params;
	struct deltic_params	drp_params;

	/* AQM state */
	struct deltic_vars	sce_vars;
	struct deltic_vars	ecn_vars;
	struct deltic_vars	drp_vars;

	struct deltic_jitter	jit_vars;

	/* resource tracking */
	u32	backlog;

	u32 	dummy;

	/* statistics */
	u64	ce_marks;
	u64	sce_marks;
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

static inline s64 ns_scaled_weight(u64 a, u64 wa, u64 b, u64 wb)
{
	u64 ab = a * wa + b * wb;
	return div64_ul(ab, NSEC_PER_SEC);
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

	if(!q->backlog)  // queue just became non-empty
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

			deltic_enqueue(segs, sch, to_free);
		}

		qdisc_tree_reduce_backlog(sch, 1-numsegs, len-slen);
		consume_skb(skb);

		return NET_XMIT_SUCCESS;
	}

	/* prepare and enqueue */
	deltic_set_cb(skb, now, 0);

	enqueue_bulk(q, skb);

	sch->q.qlen++;
	q->backlog += len;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* deltic_dequeue(struct Qdisc *sch)
{
	struct deltic_sched_data *q = qdisc_priv(sch);
	ktime_t now = ktime_get(), enq_time;
	struct sk_buff *skb;
	u32 len;
	u64 jitter, sojourn;
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
	enq_time = deltic_get_enqueue_time(skb);
	jitter   = deltic_jitter_estimate(&q->jit_vars, now);
	sojourn  = deltic_correct_sojourn(enq_time, now, jitter);

	mark_sce = q->sce_params.resonance && deltic_control(&q->sce_vars, &q->sce_params, now, sojourn);
	mark_ecn = q->ecn_params.resonance && deltic_control(&q->ecn_vars, &q->ecn_params, now, sojourn);
	drop     = q->drp_params.resonance && deltic_control(&q->drp_vars, &q->drp_params, now, sojourn);

	if(mark_sce && !mark_ecn && !drop)
		if(INET_ECN_set_ect1(skb))
			q->sce_marks++;

	if(mark_ecn && !drop) {
		if(INET_ECN_set_ce(skb))
			q->ce_marks++;
		else
			drop = true;
	}

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
	[TCA_DELTIC_FREQ_DROP]   	= { .type = NLA_U32 },  // resonance frequency (16.16) for drop controller
	[TCA_DELTIC_FREQ_ECN]   	= { .type = NLA_U32 },  // resonance frequency (16.16) for ECN controller
	[TCA_DELTIC_FREQ_SCE]   	= { .type = NLA_U32 },  // resonance frequency (16.16) for SCE controller
//	[TCA_DELTIC_FREQ_SIGNAL]	= { .type = NLA_U32 },  // baseline signalling frequency for all controllers
};

static void deltic_parameterise(struct deltic_params *p, const u32 res_freq)
{
	p->resonance = res_freq;

	if(res_freq)
		p->target = div64_ul(NSEC_PER_SEC * (1ULL << FREQ_SHIFT), res_freq);
	else
		p->target = NSEC_PER_SEC;
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

	if (tb[TCA_DELTIC_FREQ_DROP])
		deltic_parameterise(&q->drp_params, nla_get_u32(tb[TCA_DELTIC_FREQ_DROP]));

	if (tb[TCA_DELTIC_FREQ_ECN])
		deltic_parameterise(&q->ecn_params, nla_get_u32(tb[TCA_DELTIC_FREQ_ECN]));

	if (tb[TCA_DELTIC_FREQ_SCE])
		deltic_parameterise(&q->sce_params, nla_get_u32(tb[TCA_DELTIC_FREQ_SCE]));

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

static int deltic_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct nlattr *stats = nla_nest_start_noflag(d->skb, TCA_STATS_APP);
	struct deltic_sched_data *q = qdisc_priv(sch);

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

	PUT_STAT_U64(JITTER_EST, q->jit_vars.jitter);
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

static int deltic_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct deltic_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	sch->limit = 10240;

	deltic_parameterise(&q->drp_params,   8 << FREQ_SHIFT);  // 125ms target for hard dropping
	deltic_parameterise(&q->ecn_params,  40 << FREQ_SHIFT);  //  25ms target for ECN marking
	deltic_parameterise(&q->sce_params, 200 << FREQ_SHIFT);  //   5ms target for SCE marking

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
	.dump_stats	=	deltic_dump_stats,
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
