// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that marks SCE in proportion to queue busy (non-empty)
 * time, converging on an operating point with low delay and high utilization.
 *
 * Aside from the hard limit, Quartz has a single parameter, the target,
 * representing the target time for the queue to return to busy before
 * returning to idle. It can also be thought of as the maximum tolerable burst
 * before utilization may be impacted.
 */

#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

/* AQM defaults (temporary until config code is in place) */
#define DEFAULT_LIMIT 25
#define DEFAULT_TARGET 1 * NSEC_PER_MSEC

/* Debugging */
//#define PRINT_BAR
//#define PRINT_MARK
//#define PRINT_RESPONSIVENESS

struct quartz_params {
	u32 target;
};

struct quartz_sched_data {
	struct quartz_params params;
	u32 target_floor;
	u32 target_ceil;
	u8 responsiveness;
	u8 max_responsiveness;
	u32 mark;
	u32 wall;
	ktime_t start;
	ktime_t prior;
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

static void print_mark(u32 mark) {
#ifdef PRINT_MARK
	printk("mark %x\n", mark);
#endif
}

static void print_responsiveness(u8 responsiveness) {
#ifdef PRINT_RESPONSIVENESS
	printk("responsiveness %u\n", responsiveness);
#endif
}

static s32 quartz_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	int l0 = qdisc_qlen(sch);
	int r;

	if (unlikely(l0 >= sch->limit))
		return qdisc_drop(skb, sch, to_free);

	r = qdisc_enqueue_tail(skb, sch);
	if (r != NET_XMIT_SUCCESS)
		return r;

	if (!l0) {
		q->start = now;
		q->prior = now;
	}

	print_bar(qdisc_qlen(sch));

	return NET_XMIT_SUCCESS;
}

static void handle_idle(struct quartz_sched_data *q, ktime_t now, s64 busy_ns) {
	if (busy_ns < q->target_floor) {
		if (q->responsiveness) {
			q->responsiveness--;
			q->wall = U32_MAX >> q->responsiveness;
			print_responsiveness(q->responsiveness);
		}
	} else if (busy_ns > q->target_ceil) {
		if (q->responsiveness < q->max_responsiveness) {
			q->responsiveness++;
			q->wall = U32_MAX >> q->responsiveness;
			print_responsiveness(q->responsiveness);
		}
	}
	q->mark = 0;
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

	if (!qdisc_qlen(sch)) {
		handle_idle(q, now, ktime_to_ns(ktime_sub(now, q->start)));
	} else {
		u64 m = q->mark + ktime_to_ns(ktime_sub(now, q->prior));
		q->mark = (m > q->wall) ? q->wall : m;
		q->prior = now;
	}

	// TODO optimize get random for responsiveness
	if (q->mark && (get_random_u32() >> q->responsiveness < q->mark))
		INET_ECN_set_ect1(skb);

	print_mark(q->mark);
	print_bar(qdisc_qlen(sch));

	return skb;
}

static int quartz_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.target = DEFAULT_TARGET;
	// more subtle adjustment has no obvious benefit
	//q->target_floor = q->params.target * 2 / 3;
	//q->target_ceil = q->params.target * 4 / 3;
	q->target_floor = q->params.target;
	q->target_ceil = q->params.target;
	q->max_responsiveness = ilog2(q->params.target);
	q->responsiveness = q->max_responsiveness / 2;
	q->wall = U32_MAX >> q->responsiveness;
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
