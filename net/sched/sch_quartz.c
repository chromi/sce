// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that marks SCE in an automatically adjusted proportion of
 * queue busy (non-empty) time, converging on an operating point with low delay
 * and high utilization.
 *
 * Quartz has a single parameter, target, representing the target busy time
 * before returning to idle. This may also be thought of as the maximum
 * tolerable burst before utilization may be impacted.
 */

#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

/* AQM defaults (temporary until config code is in place) */
#define DEFAULT_LIMIT 25
#define DEFAULT_TARGET 5 * NSEC_PER_MSEC

/* Debugging */
//#define PRINT_BAR
//#define PRINT_IDLE
//#define PRINT_EVENTS

struct quartz_params {
	u32 target;
};

struct quartz_sched_data {
	struct quartz_params params;
	u32 target_floor;
	u32 target_ceil;
	u8 ramp;
	u8 max_ramp;
	u32 mark;
	u32 wall;
	ktime_t start;
	ktime_t prior;
	bool over_target;
};

static void print_bar(int len) {
#ifdef PRINT_BAR
#define BAR "##################################################"
	if (len) {
		printk("%.*s\n", len, BAR);
	} else {
		printk(".\n");
	}
#endif
}

static s32 quartz_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	int l0 = qdisc_qlen(sch);
	int r;

	if (unlikely(l0 >= sch->limit)) {
#ifdef PRINT_EVENTS
	printk("drop (limit %u)\n", sch->limit);
#endif
		return qdisc_drop(skb, sch, to_free);
	}

	r = qdisc_enqueue_tail(skb, sch);
	if (r != NET_XMIT_SUCCESS)
		return r;

	if (!l0) {
		q->start = now;
		q->prior = now;
		q->over_target = false;
	}

	print_bar(qdisc_qlen(sch));

	return NET_XMIT_SUCCESS;
}

static void set_ramp(struct quartz_sched_data *q, u8 ramp) {
#ifdef PRINT_EVENTS
	if (ramp != q->ramp)
		printk("ramp -> %u\n", ramp);
#endif
	q->ramp = ramp;
	q->wall = U32_MAX >> ramp;
}

static void set_mark(struct quartz_sched_data *q, u32 mark) {
#ifdef PRINT_EVENTS
	//if (q->mark && !mark)
	//	printk("mark -> 0\n");
	if (q->mark < q->wall && mark >= q->wall)
		printk("mark -> %x\n", mark);
#endif
	q->mark = mark;
}

static void on_idle(struct quartz_sched_data *q, ktime_t now, s64 busy_ns) {
	if (busy_ns < q->target_floor && q->ramp)
		set_ramp(q, q->ramp - 1);
	set_mark(q, 0);
#ifdef PRINT_IDLE
	printk("idle busy_ns=%-16lld delta=%lld\n", busy_ns,
		busy_ns - q->params.target);
#endif
}

static void on_busy(struct quartz_sched_data *q, ktime_t now, s64 busy_ns,
		s64 since_ns) {
	u64 m;

	if (!q->over_target && busy_ns > q->target_ceil) {
#ifdef PRINT_EVENTS
		s64 t = busy_ns - q->params.target;
		s64 c = busy_ns - q->target_ceil;
		printk("over target (+%lld ns, ceil +%lld ns)\n", t, c);
#endif
		if (q->ramp < q->max_ramp) {
			set_ramp(q, q->ramp + 1);
			set_mark(q, q->mark >> 1);
		}
		q->over_target = true;
	}

	m = q->mark + since_ns;
	set_mark(q, m > q->wall ? q->wall : m);
	q->prior = now;
}

static u32 rand_mark(struct quartz_sched_data *q) {
	// TODO optimize get random for ramp
	return get_random_u32() >> q->ramp;
}

static struct sk_buff* quartz_dequeue(struct Qdisc *sch)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	s64 busy_ns, since_ns;

	skb = qdisc_dequeue_head(sch);
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}

	busy_ns = ktime_to_ns(ktime_sub(now, q->start));
	since_ns = ktime_to_ns(ktime_sub(now, q->prior));
	if (!qdisc_qlen(sch))
		on_idle(q, now, busy_ns);
	else
		on_busy(q, now, busy_ns, since_ns);

	if (q->mark && (rand_mark(q) < q->mark))
		INET_ECN_set_ect1(skb);

	print_bar(qdisc_qlen(sch));

	return skb;
}

static int quartz_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.target = DEFAULT_TARGET;
	q->target_floor = q->params.target / 2;
	q->target_ceil = q->params.target * 2;
	q->max_ramp = ilog2(q->params.target);
	q->ramp = q->max_ramp / 2;
	q->wall = U32_MAX >> q->ramp;
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
