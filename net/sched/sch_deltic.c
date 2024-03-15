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


bool deltic_control(struct deltic_vars *vars,
		       const struct deltic_params *p,
		       const ktime_t now,
		       const u64 sojourn)
{
	// Delta-Sigma control is essentially a PID controller without the P term:

	// slope = (sojourn - last_sojourn) / (now - then)
	// acc = max(0, acc + (slope + sojourn - target) * (now - then) * resonant_freq)

	// The above simplifies by cancelling the division in slope calculation
	// against the multiplication by the same quantity:

	// acc = max(0, acc + ((sojourn - last_sojourn) + (sojourn - target) * (now - then)) * resonant_freq)

	// Since we still multiply two fixed-point values (times in nanoseconds), we need to
	// correct that before adding the result to other time values.  Our helper function
	// ns_scaled_mul() does that for us.  There are some other fixed-point oddities which
	// we also need to take care of.

	bool mark = false;
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
		s64 sigma = ns_scaled_mul(sojourn - p->target, interval);

		vars->accumulator += ((delta + sigma) * p->resonance) >> FREQ_SHIFT;
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
		// osc += acc * (now - then) * resonance
		// Issue a mark event when osc overflows.

		vars->oscillator += (ns_scaled_mul(vars->accumulator, interval) * p->resonance) >> FREQ_SHIFT;
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


u64 deltic_jitter_estimate(struct deltic_jitter *jit, const ktime_t now)
{
	// We define jitter as the typical interval between transmission opportunities, each of which results
	// in the dequeuing of one or more packets.  Intervals during which the queue is empty are ignored.
	// This quantity is estimated by taking an interval-weighted moving average of intervals.
	// The calculated jitter is returned for convenience.
	u64 interval = min((u64) max((s64) 0, (s64) ktime_to_ns(ktime_sub(now, jit->timestamp))), (u64) NSEC_PER_SEC);
	u64 jitter = ns_scaled_weight(interval, interval, jit->jitter, NSEC_PER_SEC - interval);

	jit->jitter = jitter;
	jit->timestamp = now;
	return jitter;
}
