// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that modulates an SCE marking probability proportionally to
 * queue busy and idle time, converging on an operating point with low delay
 * and high utilization.
 */

#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

/**
 * Responsiveness:
 * 0: 4.29s
 * 1: 2.15s
 * 2: 1.07s
 * 3: 537ms
 * 4: 268ms
 * 5: 134ms
 * 6: 67ms
 * 7: 33ms
 * 8: 17ms
 */

/* AQM defaults (temporary until config code is in place) */
#define DEFAULT_LIMIT 25
#define DEFAULT_RESPONSIVENESS 3
#define DEFAULT_BOOST 0
#define DEFAULT_FLOOR 0

struct quartz_params {
	u8 responsiveness;
	s8 boost;
	u8 floor;
};

struct quartz_sched_data {
	struct quartz_params params;
	u32 mark;
	u32 wall;
	u8 ceil;
	ktime_t prior;
};

static void update_idle(ktime_t now, struct quartz_params *p,
			struct quartz_sched_data *q)
{
	s64 i = ktime_to_ns(ktime_sub(now, q->prior));
	if (p->boost > 0)
		i <<= p->boost;
	else if (p->boost < 0)
		i >>= -p->boost;
	q->mark = (i >= q->mark) ? 0 : q->mark - i;
	q->prior = now;
}

static void update_busy(ktime_t now, struct quartz_params *p,
			struct quartz_sched_data *q)
{
	s64 b = ktime_to_ns(ktime_sub(now, q->prior));
	u64 m = q->mark + b;
	q->mark = (m > q->wall) ? q->wall : m;
	q->prior = now;
}

static s32 quartz_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct quartz_params *p = &q->params;
	int l0 = qdisc_qlen(sch), l1;
	int r;

	if (unlikely(l0 >= sch->limit))
		return qdisc_drop(skb, sch, to_free);

	r = qdisc_enqueue_tail(skb, sch);
	if (r != NET_XMIT_SUCCESS)
		return r;
	l1 = qdisc_qlen(sch);

	if (l0 == p->floor)
		update_idle(now, p, q);
	else if (l0 == q->ceil)
		q->prior = now;

	//printk("%.*s\n", l1,
	//	"##################################################");

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* quartz_dequeue(struct Qdisc *sch)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct quartz_params *p = &q->params;
	struct sk_buff *skb;
	int l0 = qdisc_qlen(sch), l1;

	skb = qdisc_dequeue_head(sch);
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	l1 = qdisc_qlen(sch);

	if (l0 >= q->ceil)
		update_busy(now, p, q);

	if (l1 == p->floor)
		q->prior = now;
	else if (l1 < p->floor)
		update_idle(now, p, q);

	//printk("mark %x\n", q->mark);
	if (q->mark && get_random_u32() >> p->responsiveness < q->mark)
		INET_ECN_set_ect1(skb);

	/*
	if (l1) {
		printk("%.*s\n", l1,
			"##################################################");
	} else {
		printk(".\n");
	}
	*/

	return skb;
}

static int quartz_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.responsiveness = DEFAULT_RESPONSIVENESS;
	q->params.boost = DEFAULT_BOOST;
	q->params.floor = DEFAULT_FLOOR;
	q->ceil = q->params.floor + 1;
	q->wall = U32_MAX >> q->params.responsiveness;
	q->prior = ktime_get();

	sch->limit = DEFAULT_LIMIT;

	if (sch->limit >= 1)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;

	return 0;
}

static void quartz_reset(struct Qdisc *sch)
{
	qdisc_reset_queue(sch);
}

static int quartz_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	return 0;
}

static int quartz_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nlattr *opts;

	opts = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (opts == NULL)
		goto nla_put_failure;
	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

struct Qdisc_ops quartz_qdisc_ops __read_mostly = {
	.id		=	"quartz",
	.priv_size	=	sizeof(struct quartz_sched_data),
	.enqueue	=	quartz_enqueue,
	.dequeue	=	quartz_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	quartz_init,
	.reset		=	quartz_reset,
	.change		=	quartz_change,
	.dump		=	quartz_dump,
	.owner		=	THIS_MODULE,
};

static int __init quartz_module_init(void)
{
	return register_qdisc(&quartz_qdisc_ops);
}

static void __exit quartz_module_exit(void)
{
	unregister_qdisc(&quartz_qdisc_ops);
}

module_init(quartz_module_init)
module_exit(quartz_module_exit)
MODULE_AUTHOR("Pete Heist");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Quartz AQM.");
