// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that marks SCE in proportion to queue busy (non-empty)
 * time, and adjusts the ramp to aim for the specified busy time target,
 * hovering around an operating point with low delay and high utilization.
 * Quartz pays no attention to the queue length, other than to enforce a hard
 * limit.
 *
 * Parameters:
 *
 *   target    the target busy time before returning to idle
 *   interval  the period between ramp updates
 *   limit     hard limit, in packets
 *
 * TODO
 * - implement marking strategy generically for easier experimentation
 * - possibly return ramp to 32 bit
 * - optimize get_random call for size of ramp
 */

#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

/* AQM defaults (temporary until config code is in place) */
#define DEFAULT_LIMIT 50
#define DEFAULT_TARGET 10 * NSEC_PER_MSEC
#define DEFAULT_INTERVAL 200 * NSEC_PER_MSEC

/* hard defines */
#define RAMP_BASE 32

/* interval_saw bitmask values */
enum {
	SAW_NONE		= 0,
	SAW_OVER_TARGET		= BIT(0),
	SAW_UNDER_TARGET	= BIT(1)
};

/* Debugging */
//#define PRINT_BAR
//#define PRINT_IDLE
//#define PRINT_EVENTS

struct quartz_params {
	u32	target;
	u32	interval;
};

struct quartz_sched_data {
	struct quartz_params params;

	u8	ramp;
	u8	ramp_shift;
	u8	ramp_max;
	u64	mark;
	u64	wall;
	ktime_t	busy_start;
	ktime_t	busy_prior;
	ktime_t	interval_end;
	u8	interval_saw;
};

static void reset_interval(struct quartz_sched_data *q, ktime_t now)
{
	q->interval_end = ktime_add(now, q->params.interval);
	q->interval_saw = SAW_NONE;
}

static void set_ramp(struct quartz_sched_data *q, u8 ramp, ktime_t now)
{
#ifdef PRINT_EVENTS
	if (ramp != q->ramp)
		printk("ramp -> %u\n", ramp);
	if (ramp >= q->ramp_max)
		printk("hit max ramp %u\n", ramp);
#endif
	q->ramp = ramp;
	q->ramp_shift = RAMP_BASE + (ramp - 1);
	q->wall = U64_MAX >> q->ramp_shift;
}

static void set_mark(struct quartz_sched_data *q, u64 mark)
{
/*
#ifdef PRINT_EVENTS
	static bool p;
	if (!p) {
		if (mark >= q->wall) {
			printk("mark -> %llx\n", mark);
			p = true;
		}
	} else {
		p = (mark > 0);
	}
#endif
*/
	q->mark = mark;
}

static void increment_ramp(struct quartz_sched_data *q, ktime_t now)
{
	if (q->ramp < q->ramp_max) {
		set_ramp(q, q->ramp + 1, now);
		set_mark(q, q->mark >> 1);
	}
}

static void decrement_ramp(struct quartz_sched_data *q, ktime_t now)
{
	if (q->ramp) {
		set_ramp(q, q->ramp - 1, now);
		set_mark(q, q->mark << 1);
	}
}

static void on_interval_end(struct quartz_sched_data *q, ktime_t now)
{
	switch (q->interval_saw) {
	case SAW_NONE:
	case SAW_OVER_TARGET:
		increment_ramp(q, now);
		break;
	case SAW_UNDER_TARGET:
		decrement_ramp(q, now);
		break;
	}
	reset_interval(q, now);
}

static void on_idle(struct quartz_sched_data *q, ktime_t now)
{
	struct quartz_params *p = &q->params;
	s64 t = ktime_to_ns(ktime_sub(now, q->busy_start));

	q->interval_saw |= (t > p->target) ? SAW_OVER_TARGET : SAW_UNDER_TARGET;

	if (ktime_after(now, q->interval_end))
		on_interval_end(q, now);

	set_mark(q, 0);

#ifdef PRINT_IDLE
	printk("busy=%-16lldns delta=%lld\n", t, t - p->target);
#endif
}

static void on_busy(struct quartz_sched_data *q, ktime_t now)
{
	if (ktime_after(now, q->interval_end))
		on_interval_end(q, now);

	if (q->ramp) {
		u64 m = q->mark + ktime_to_ns(ktime_sub(now, q->busy_prior));
		set_mark(q, m > q->wall ? q->wall : m);
	}

	q->busy_prior = now;
}

static u64 get_random_mark(struct quartz_sched_data *q)
{
	return get_random_u64() >> q->ramp_shift;
}

static void mark_random(struct quartz_sched_data *q, struct sk_buff *skb)
{
	if (!q->mark || !q->ramp)
		return;

	if (q->ramp < q->ramp_max) {
		if (get_random_mark(q) < q->mark)
			INET_ECN_set_ect1(skb);
	} else {
		INET_ECN_set_ect1(skb);
	}
}

static void print_bar(int len)
{
#ifdef PRINT_BAR
#define BAR "##################################################"
	if (len)
		printk("%.*s\n", len, BAR);
	else
		printk(".\n");
#endif
}

static s32 quartz_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	int l0 = qdisc_qlen(sch);
	int r;

	if (unlikely(sch->limit && l0 >= sch->limit)) {
#ifdef PRINT_EVENTS
		printk("drop (limit %u)\n", sch->limit);
#endif
		return qdisc_drop(skb, sch, to_free);
	}

	r = qdisc_enqueue_tail(skb, sch);
	if (r != NET_XMIT_SUCCESS)
		return r;

	if (!l0) {
		q->busy_start = now;
		q->busy_prior = now;
		if (q->interval_saw == SAW_NONE)
			reset_interval(q, now);
	}

	print_bar(qdisc_qlen(sch));

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* quartz_dequeue(struct Qdisc *sch)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	skb = qdisc_dequeue_head(sch);
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	if (!qdisc_qlen(sch))
		on_idle(q, now);
	else
		on_busy(q, now);

	mark_random(q, skb);

	print_bar(qdisc_qlen(sch));

	return skb;
}

static int quartz_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.target = DEFAULT_TARGET;
	q->params.interval = DEFAULT_INTERVAL;
	q->ramp_max = ilog2(q->params.target / 2);
	set_ramp(q, 0, 0);

	sch->limit = DEFAULT_LIMIT;
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
