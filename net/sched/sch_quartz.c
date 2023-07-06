// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that modulates a signaling frequency using queue busy and
 * idle time.
 */

#include <linux/printk.h> // debug
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

// TODO remove hard-coding of AQM parameters

//#define DEFAULT_QUARTZ_LIMIT 1000
#define DEFAULT_QUARTZ_LIMIT 83 // 20 ms @ 50 Mbps
#define DEFAULT_BURST 0*NSEC_PER_MSEC
#define DEFAULT_IDLE_SHIFT -1
#define DEFAULT_WALL_SHIFT 2 // wall == 2^30 ns (~1.07 sec)

struct quartz_params {
	u32 burst_ns;
	s8 idle_shift;
	u8 wall_shift;
};

struct quartz_sched_data {
	struct quartz_params params;

	ktime_t busy;
	ktime_t prior;
	ktime_t idle;
	u32 wall;
	s64 mark; // TODO consider making mark 32-bit
};

static s32 quartz_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	if (unlikely(sch->q.qlen >= sch->limit))
		return qdisc_drop(skb, sch, to_free);

	if (!sch->q.qlen) {
		ktime_t now = ktime_get();
		q->busy = now;
		q->prior = now;
		if (q->idle) {
			ktime_t d = ktime_sub(now, q->idle);
			struct quartz_params *p = &q->params;
			if (p->idle_shift > 0) {
				d >>= p->idle_shift;
			} else if (p->idle_shift < 0) {
				d <<= -p->idle_shift;
			}
			q->mark -= ktime_to_ns(d);
			if (q->mark < 0) {
				q->mark = 0;
			}
		}
	}

	return qdisc_enqueue_tail(skb, sch);
}

static struct sk_buff* quartz_dequeue(struct Qdisc *sch)
{
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb = qdisc_dequeue_head(sch);
	ktime_t now = ktime_get();
	ktime_t b = ktime_sub(now, q->busy);
	struct quartz_params *p = &q->params;

	if (unlikely(!skb)) {
		WARN_ON(!skb);
		q->idle = now;
		return NULL;
	}
	if (!sch->q.qlen) {
		q->idle = now;
	}
	if (ktime_to_ns(b) > p->burst_ns) {
		q->mark += ktime_to_ns(ktime_sub(now, q->prior));
		if (q->mark > q->wall) {
			q->mark = q->wall;
		}
	}
	q->prior = now;
	if (get_random_u32() >> p->wall_shift <= q->mark) {
		INET_ECN_set_ect1(skb);
	}

	return skb;
}

static int quartz_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.burst_ns = DEFAULT_BURST;
	q->params.idle_shift = DEFAULT_IDLE_SHIFT;
	q->params.wall_shift = DEFAULT_WALL_SHIFT;
	q->wall = ~0 >> q->params.wall_shift;

	sch->limit = DEFAULT_QUARTZ_LIMIT;

	/*
	 * TODO What should I do with TCQ_F_CAN_BYPASS?
	 * It is not clear to me what this is for. It's set by codel, but only
	 * if limit is >= 1. It's not set by red or sfb. For now, I'll use
	 * codel's behavior until I understand it better. And why wouldn't
	 * codel do this in codel_change? Can't the limit change?
	 */
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
	//struct quartz_sched_data *q = qdisc_priv(sch);

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

/*
 * TODO Is it correct to use qdisc_peek_dequeued?
 * Since we are marking SCE in the dequeue function, I think we actually need
 * to call dequeue to get a packet for peeking. Now, the documentation for
 * qdisc_peek_dequeued says it's for non-work-conserving qdiscs, yet I think
 * there are many work-conserving qdiscs using it. So, this is confusing.
 */

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
