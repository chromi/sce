#ifndef __NET_SCHED_DELTIC_H
#define __NET_SCHED_DELTIC_H

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

/* DelTiC (Delay Time Control) AQM discipline
 *
 * Copyright (C) 2022-4 Jonathan Morton <chromatix99@gmail.com>
 *
 * DelTiC is a fully time-domain AQM based on a delta-sigma control loop and
 * a numerically-controlled oscillator.  Delta-sigma means a PID controller
 * lacking a Proportional term, with the D term accumulated into the I term.
 */

struct deltic_params {
	u32 target;     /* sojourn time in nanoseconds */
	u32 resonance;  /* target queue depth expressed as a frequency, Hz, 16.16 fixed-point */
};

struct deltic_vars {
	s64 accumulator;    // for I part of PID controller
	u64 history;// for D part of PID controller
	ktime_t timestamp;  // time last packet was processed
	u64 oscillator;     // Numerically Controlled Oscillator's accumulator
};

struct deltic_jitter {
	ktime_t timestamp;  // time of last txop or queue becoming non-empty
	u64 jitter; // interval-weighted moving average of jitter, in nanoseconds
};

struct deltic_skb_cb {
	ktime_t enqueue_time;
	u16 flow;
};


static inline struct deltic_skb_cb *get_deltic_cb(const struct sk_buff *skb)
{
	qdisc_cb_private_validate(skb, sizeof(struct deltic_skb_cb));
	return (struct deltic_skb_cb *)qdisc_skb_cb(skb)->data;
}

static inline ktime_t deltic_get_enqueue_time(const struct sk_buff *skb)
{
	return get_deltic_cb(skb)->enqueue_time;
}

static inline u16 deltic_get_flow(const struct sk_buff *skb)
{
	return get_deltic_cb(skb)->flow;
}

static inline void deltic_set_cb(struct sk_buff *skb, const ktime_t now, u16 flow)
{
	struct deltic_skb_cb *cb = get_deltic_cb(skb);

	cb->enqueue_time = now;
	cb->flow = flow;
}


static inline u64 deltic_correct_sojourn(const ktime_t enq_time, const ktime_t deq_time, const u64 jitter)
{
	// Sojourn time is essentially the difference between enqueue and dequeue times.
	u64 sojourn = ktime_to_ns(ktime_sub(deq_time, enq_time));

	// Jitter can result from the serialisation time of individual packets or aggregates thereof,
	// or a sparse availability of transmission opportunities (eg. DOCSIS, WiFi, or FQ).
	// We "forgive" the estimated jitter from the sojourn time of the queue to avoid emitting
	// spurious congestion signals.  It is thus no longer necessary to explicitly calculate
	// serialisation times, etc. for this purpose.
	return (sojourn > jitter) ? sojourn - jitter : 0;
}


bool deltic_control(struct deltic_vars *vars,
		    const struct deltic_params *p,
		    const ktime_t now,
		    const u64 sojourn);

u64 deltic_jitter_estimate(struct deltic_jitter *jit, const ktime_t now);


#endif
