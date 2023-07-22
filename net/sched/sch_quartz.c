// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* Quartz Active Queue Management Queueing Discipline
 *
 * Copyright (C) 2023 Pete Heist <pete@heistp.net>
 *
 * Quartz is an AQM that aims for low queueing delay with good utilization by
 * marking SCE and CE such that the queue periodically and briefly returns to
 * idle. It does this by marking in proportion to the queue sojourn time,
 * accumulated across the queue busy time. The marking ramp is modulated
 * according to a target busy time, thus adapting to the carried load.
 *
 * Parameters:
 *
 *   target         the target busy time before returning to idle
 *   interval       the period between ramp updates
 *   floor          number of packets in queue at which it's considered busy
 *   sojourn_limit  delay time at which all packets are marked CE or dropped
 *   limit          hard limit, in packets
 */

#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/inet_ecn.h>

/* AQM defaults (temporary until config code is in place) */
#define DEFAULT_TARGET (5 * NSEC_PER_MSEC)
#define DEFAULT_INTERVAL (100 * NSEC_PER_MSEC)
#define DEFAULT_FLOOR 0
#define DEFAULT_SOJOURN_LIMIT (50 * NSEC_PER_MSEC)
#define DEFAULT_LIMIT 1000

/* hard defines */
#define SHIFT_CE 2
#define SHIFT_SCE 8
#define MARK_MIN 0
#define MARK_MAX (U64_MAX >> SHIFT_CE)
#define MARK_MAX_SCE (U64_MAX >> SHIFT_SCE)
#define RAMP_MIN 0
#define RAMP_MAX (2 * (64 - SHIFT_CE))
#define RAMP_INFINITE U8_MAX

#define SCE_DSCP_RTT_FAIR 3
#define SCE_DSCP_MAX_MIN_FAIR 7
#define SCE_DSCP_POWER_FAIR 11

/* Debugging */
//#define PRINT_EVENTS
//#define PRINT_QLEN_BAR
//#define PRINT_IDLE
//#define PRINT_MARK

struct quartz_params {
	u32	target;
	u32	interval;
	u32	floor;
	u32	sojourn_limit;
};

struct quartz_sched_data {
	struct quartz_params params;

	u8	ramp;
	u64	mark;
	ktime_t	busy_start;
	ktime_t	busy_prior;
	ktime_t	interval_end;
	ktime_t	interval_over;
	ktime_t	interval_under;
};

struct quartz_skb_cb {
	ktime_t	enqueue_time;
};

/*
 * utility functions
 */

static struct quartz_skb_cb *quartz_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct quartz_skb_cb));
	return (struct quartz_skb_cb *)qdisc_skb_cb(skb)->data;
}

static void set_enqueue_time(struct sk_buff *skb, ktime_t t)
{
	quartz_cb(skb)->enqueue_time = t;
}

static ktime_t sojourn_time(struct sk_buff *skb, ktime_t now)
{
	return ktime_sub(now, quartz_cb(skb)->enqueue_time);
}

static u8 dscp(struct sk_buff *skb)
{
	int l = skb_network_offset(skb);

	switch (skb_protocol(skb, true)) {
	case htons(ETH_P_IP):
		l += sizeof(struct iphdr);
		if (!pskb_may_pull(skb, l))
			return 0;
		return ipv4_get_dsfield(ip_hdr(skb)) >> 2;
	case htons(ETH_P_IPV6):
		l += sizeof(struct ipv6hdr);
		if (!pskb_may_pull(skb, l))
			return 0;
		return ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;
	default:
		return 0;
	};
}

static bool is_sce_dscp(u8 dscp)
{
	switch (dscp) {
	case SCE_DSCP_RTT_FAIR:
	case SCE_DSCP_MAX_MIN_FAIR:
	case SCE_DSCP_POWER_FAIR:
		return true;
	}
	return false;
}

static void print_qlen_bar(int len)
{
#ifdef PRINT_QLEN_BAR
#define BAR "##################################################"
	if (len)
		printk("%.*s\n", len, BAR);
	else
		printk(".\n");
#endif
}

/*
 * quartz_sched_data functions
 */

static u64 ktime_to_mark(struct quartz_sched_data *q, ktime_t t)
{
	if (likely(t > 0)) {
		if (q->ramp < RAMP_INFINITE) {
			u64 n = ktime_to_ns(t);
			u64 m = n << (q->ramp >> 1);
			if (!(q->ramp & 1))
				m -= (n >> 1);
			return m;
		}
		return MARK_MAX;
	}
	return 0;
}

static void set_mark(struct quartz_sched_data *q, u64 mark)
{
#ifdef PRINT_MARK
	printk("mark -> %llx\n", mark);
#endif
	q->mark = mark;
}

static void set_ramp(struct quartz_sched_data *q, u8 ramp)
{
#ifdef PRINT_EVENTS
	if (ramp != q->ramp)
		printk("ramp -> %u\n", ramp);
#endif
	q->ramp = ramp;
}

static void increment_ramp(struct quartz_sched_data *q)
{
	if (q->ramp < RAMP_MAX)
		set_ramp(q, q->ramp + 1);
	else if (q->ramp != RAMP_INFINITE)
		set_ramp(q, RAMP_INFINITE);
}

static void decrement_ramp(struct quartz_sched_data *q)
{
	if (q->ramp == RAMP_INFINITE)
		set_ramp(q, RAMP_MAX);
	else if (q->ramp > RAMP_MIN)
		set_ramp(q, q->ramp - 1);
}

static bool sojourn_over_limit(struct quartz_sched_data *q,
			       struct sk_buff *skb,
			       ktime_t now)
{
	u32 l = q->params.sojourn_limit;
	return l && ktime_to_ns(sojourn_time(skb, now)) > l ? true : false;
}

static void mark_sce_random(struct quartz_sched_data *q, struct sk_buff *skb)
{
	if (q->mark >= MARK_MAX_SCE ||
	   (q->mark && (get_random_u64() >> SHIFT_SCE) < q->mark))
		INET_ECN_set_ect1(skb);
}

static bool mark_ce_random(struct quartz_sched_data *q, struct sk_buff *skb)
{
	if (q->mark >= MARK_MAX ||
	   (q->mark && (get_random_u64() >> SHIFT_CE) < q->mark))
		return !INET_ECN_set_ce(skb);
	return false;
}

static void reset_interval(struct quartz_sched_data *q, ktime_t now)
{
	q->interval_end = ktime_add(now, q->params.interval);
	q->interval_over = 0;
	q->interval_under = 0;
}

static void on_busy(struct quartz_sched_data *q, ktime_t now)
{
	q->busy_start = now;
	q->busy_prior = now;
	if (unlikely(!q->interval_end))
		reset_interval(q, now);
}

static void on_interval_end(struct quartz_sched_data *q, ktime_t now)
{
	if ((q->interval_over > q->interval_under << 1) ||
	    (!q->interval_over && !q->interval_under))
		increment_ramp(q);
	else if (q->interval_under > q->interval_over << 1)
		decrement_ramp(q);

	reset_interval(q, now);
}

static void on_busy_dequeue(struct quartz_sched_data *q,
			    struct sk_buff *skb,
			    ktime_t now)
{
	ktime_t b;
	u64 m, i;

	if (ktime_after(now, q->interval_end))
		on_interval_end(q, now);

	b = ktime_sub(now, q->busy_prior);
	i = ktime_to_mark(q, b) * ktime_to_ns(sojourn_time(skb, now));
	m = (i >= (MARK_MAX - q->mark) ? MARK_MAX : q->mark + i);
	set_mark(q, m);

	q->busy_prior = now;
}

static void on_idle(struct quartz_sched_data *q, ktime_t now)
{
	struct quartz_params *p = &q->params;
	s64 t = ktime_to_ns(ktime_sub(now, q->busy_start));

	if (t > p->target)
		q->interval_over += (t - p->target);
	else
		q->interval_under += (p->target - t);

	set_mark(q, MARK_MIN);

#ifdef PRINT_IDLE
	printk("busy=%-16lldns delta=%lld\n", t, t - p->target);
#endif
}

/*
 * qdisc op functions
 */

static s32 quartz_enqueue(struct sk_buff *skb,
			  struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct quartz_params *p = &q->params;
	int len0 = qdisc_qlen(sch);
	int r;

	if (unlikely(sch->limit && len0 >= sch->limit)) {
#ifdef PRINT_EVENTS
		printk("drop at packet limit %u\n", sch->limit);
#endif
		return qdisc_drop(skb, sch, to_free);
	}

	set_enqueue_time(skb, now);

	r = qdisc_enqueue_tail(skb, sch);
	if (r != NET_XMIT_SUCCESS)
		return r;

	if (len0 == p->floor)
		on_busy(q, now);

	print_qlen_bar(qdisc_qlen(sch));

	return NET_XMIT_SUCCESS;
}

static struct sk_buff* quartz_dequeue(struct Qdisc *sch)
{
	ktime_t now = ktime_get();
	struct quartz_sched_data *q = qdisc_priv(sch);
	struct quartz_params *p = &q->params;
	struct sk_buff *skb;
	int len1;
	bool drop = false;

	skb = qdisc_dequeue_head(sch);
	if (unlikely(!skb)) {
		WARN_ON(!skb);
		return NULL;
	}
	len1 = qdisc_qlen(sch);

	if (len1 >= p->floor)
		on_busy_dequeue(q, skb, now);

	if (is_sce_dscp(dscp(skb)))
		mark_sce_random(q, skb);
	else
		drop = mark_ce_random(q, skb);

	if (len1 == p->floor)
		on_idle(q, now);

	if (!drop && sojourn_over_limit(q, skb, now) && !INET_ECN_set_ce(skb))
		drop = true;

	if (drop && len1) {
		qdisc_tree_reduce_backlog(sch, 1, qdisc_pkt_len(skb));
		qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return quartz_dequeue(sch);
	}

	print_qlen_bar(len1);

	qdisc_bstats_update(sch, skb);

	return skb;
}

static int quartz_init(struct Qdisc *sch,
		       struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct quartz_sched_data *q = qdisc_priv(sch);

	memset(q, 0, sizeof(*q));
	q->params.target = DEFAULT_TARGET;
	q->params.interval = DEFAULT_INTERVAL;
	q->params.floor = DEFAULT_FLOOR;
	q->params.sojourn_limit = DEFAULT_SOJOURN_LIMIT;
	set_ramp(q, RAMP_MIN);

	sch->limit = DEFAULT_LIMIT;
	sch->flags &= ~TCQ_F_CAN_BYPASS;

	return 0;
}

static void quartz_reset(struct Qdisc *sch)
{
	qdisc_reset_queue(sch);
}

static int quartz_change(struct Qdisc *sch,
			 struct nlattr *opt,
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
