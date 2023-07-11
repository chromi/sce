// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that marks SCE in proportion to queue busy (non-empty)
 * time. The ramp is adjusted based on the specified busy time target,
 * converging on an operating point with low delay and high utilization. Quartz
 * pays no attention to the queue depth, other than to enforce a hard limit.
 *
 * Parameters:
 *
 *   target     the target busy time before returning to idle
 *   busy_hold  the minimum allowed time between ramp increases on busy
 *   idle_hold  the minimum allowed time between ramp decreases on idle
 *   limit      hard limit, in packets
 *
 * TODO
 * - make sure mark and ramp can't overflow in any way
 * - possibly return ramp to 32 bit
 * - check wisdom of resetting busy_held and idle_held in set_ramp
 * - optimize get_random call for size of ramp
 */

#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

/* AQM defaults (temporary until config code is in place) */
#define DEFAULT_LIMIT 50
#define DEFAULT_TARGET 5 * NSEC_PER_MSEC
#define DEFAULT_IDLE_HOLD 10 * NSEC_PER_MSEC
#define DEFAULT_BUSY_HOLD 100 * NSEC_PER_MSEC

/* hard defines */
#define RAMP_BASE 32
#define CEILING_FACTOR 2

/* Debugging */
//#define PRINT_BAR
//#define PRINT_IDLE
//#define PRINT_TARGET
//#define PRINT_EVENTS

struct quartz_params {
	u32	target;
	u32	idle_hold;
	u32	busy_hold;
};

struct quartz_sched_data {
	struct quartz_params params;

	u32	target_floor;
	u32	target_ceil;
	ktime_t busy_held;
	ktime_t idle_held;
	u8	ramp;
	u8	ramp_shift;
	u8	ramp_max;
	u64	mark;
	u64	wall;
	ktime_t	start;
	ktime_t	prior;
#ifdef PRINT_TARGET
	u8	busy_hold_n;
#endif
};

static void print_bar(int len) {
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
		q->busy_held = ktime_add(now, ns_to_ktime(q->target_ceil));
#ifdef PRINT_TARGET
		q->busy_hold_n = 1;
#endif
	}

	print_bar(qdisc_qlen(sch));

	return NET_XMIT_SUCCESS;
}

static void set_ramp(struct quartz_sched_data *q, u8 ramp, ktime_t now) {
#ifdef PRINT_EVENTS
	if (ramp != q->ramp)
		printk("ramp -> %u\n", ramp);
#endif
	q->ramp = ramp;
	q->ramp_shift = RAMP_BASE + (ramp - 1);
	q->wall = U64_MAX >> q->ramp_shift;
	/*
	if (!q->ramp) {
		q->busy_held = now;
		q->idle_held = now;
	}
	*/
}

static void set_mark(struct quartz_sched_data *q, u64 mark) {
#ifdef PRINT_EVENTS
	if (q->mark < q->wall && mark >= q->wall)
		printk("mark -> %llx\n", mark);
#endif
	q->mark = mark;
}

static void on_idle(struct quartz_sched_data *q, ktime_t now, s64 busy_ns) {
	if (busy_ns < q->target_floor && ktime_after(now, q->idle_held)) {
#ifdef PRINT_TARGET
		s64 t = q->target_floor - busy_ns;
		s64 h = ktime_to_ns(ktime_sub(now, q->idle_held));
		printk("under target (-%lld ns, held +%lld ns)\n", t, h);
#endif
		if (q->ramp)
			set_ramp(q, q->ramp - 1, now);

		q->idle_held = ktime_add(now, ns_to_ktime(q->params.idle_hold));
	}
	set_mark(q, 0);
#ifdef PRINT_IDLE
	printk("idle busy_ns=%-16lld delta=%lld\n", busy_ns,
		busy_ns - q->params.target);
#endif
}

static void on_busy(struct quartz_sched_data *q, ktime_t now, s64 busy_ns,
		s64 since_ns) {
	u64 m;

	if (ktime_after(now, q->busy_held)) {
#ifdef PRINT_TARGET
		s64 t = busy_ns - q->params.target;
		s64 h = ktime_to_ns(ktime_sub(now, q->busy_held));
		printk("over target (n=%u, +%lld ns, held +%lld ns)\n",
			q->busy_hold_n, t, h);
		q->busy_hold_n++;
#endif
		if (q->ramp < q->ramp_max) {
			set_ramp(q, q->ramp + 1, now);
			set_mark(q, q->mark >> 1);
		}
		q->busy_held = ktime_add(now, ns_to_ktime(q->params.busy_hold));
	}

	if (q->ramp) {
		m = q->mark + since_ns;
		set_mark(q, m > q->wall ? q->wall : m);
	}
	q->prior = now;
}

static u64 rand_mark(struct quartz_sched_data *q) {
	return get_random_u64() >> q->ramp_shift;
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
		//INET_ECN_set_ce(skb);

	print_bar(qdisc_qlen(sch));

	return skb;
}

static int quartz_init(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.target = DEFAULT_TARGET;
	q->params.idle_hold = DEFAULT_IDLE_HOLD;
	q->params.busy_hold = DEFAULT_BUSY_HOLD;
	q->target_floor = q->params.target / CEILING_FACTOR;
	q->target_ceil = q->params.target * CEILING_FACTOR;
	q->ramp_max = ilog2(q->params.target);
	set_ramp(q, 0, 0);

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
