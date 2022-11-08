// SPDX-License-Identifier: GPL-2.0-only
/*
 * TCP LINEAR: CUBIC without the CUBIC.
 *
 * See tcp_cubic.c for details on CUBIC.
 * Instantiated as "linear-a", "linear-b", etc. with different combinations
 * of alpha/beta parameters, to explore Reno compatibility mode dynamics.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define LINEAR_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	LINEAR_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4 ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;
static int initial_ssthresh __read_mostly;

static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta_us __read_mostly = 2000;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta_us, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta_us, "spacing between ack's indicating train (usecs)");

/* BIC TCP Parameters */
struct linear {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */

	u32	alpha;		/* parameters of Reno compatibility mode */
	u32	beta;

	u32	delay_min;	/* min delay (usec) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u16	unused;
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
};

static inline void linear_reset(struct linear *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;

	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

static inline u32 linear_clock_us(const struct sock *sk)
{
	return tcp_sk(sk)->tcp_mstamp;
}

static inline void linear_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct linear *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = linear_clock_us(sk);
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = ~0U;
	ca->sample_cnt = 0;
}

static inline void linear_init(struct sock *sk, const u32 beta)
{
	struct linear *ca = inet_csk_ca(sk);

	linear_reset(ca);

	ca->alpha = 8 * (LINEAR_BETA_SCALE + beta) / 3 / (LINEAR_BETA_SCALE - beta);
	ca->beta = beta;

	if (hystart)
		linear_hystart_reset(sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

static void linearA_init(struct sock *sk)
{
	linear_init(sk, 512);  // 0.5 * 1024, per NewReno
}

static void linearB_init(struct sock *sk)
{
	linear_init(sk, 717);  // 0.7 * 1024, per CUBIC
}

static void linearC_init(struct sock *sk)
{
	linear_init(sk, 870);  // 0.85 * 1024, per ABE (RFC-8511)
}


static void linear_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_TX_START) {
		struct linear *ca = inet_csk_ca(sk);
		u32 now = tcp_jiffies32;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		/* We were application limited (idle) for a while.
		 * Shift epoch_start to keep cwnd growth to cubic curve.
		 */
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}

/*
 * Compute congestion window to use.
 */
static inline void linear_update(struct linear *ca, u32 cwnd, u32 acked)
{
	u32 delta, max_cnt;
	u32 scale = ca->alpha;

	ca->ack_cnt += acked;	/* count the number of ACKed packets */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_jiffies32 - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_jiffies32;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_jiffies32;	/* record beginning */
		ca->ack_cnt = acked;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* synchronise states */
	}

	/* TCP Friendly */
	delta = (cwnd * scale) >> 3;
	while (ca->ack_cnt > delta) {		/* update tcp cwnd */
		ca->ack_cnt -= delta;
		ca->tcp_cwnd++;
	}

	if (ca->tcp_cwnd > cwnd) {	/* if cwnd should increase */
		delta = ca->tcp_cwnd - cwnd;
		max_cnt = cwnd / delta;
		ca->cnt = max(max_cnt, 2U);
	} else {
		/* avoid cwnd increase */
		ca->cnt = 100 * cwnd;
	}
}

static void linear_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct linear *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		if (hystart && after(ack, ca->end_seq))
			linear_hystart_reset(sk);
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	linear_update(ca, tp->snd_cwnd, acked);
	tcp_cong_avoid_ai(tp, ca->cnt, acked);
}

static u32 linear_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct linear *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */
	ca->last_max_cwnd = tp->snd_cwnd;

	return max((tp->snd_cwnd * ca->beta) / LINEAR_BETA_SCALE, 2U);
}

static void linear_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		linear_reset(inet_csk_ca(sk));
		linear_hystart_reset(sk);
	}
}

/* Account for TSO/GRO delays.
 * Otherwise short RTT flows could get too small ssthresh, since during
 * slow start we begin with small TSO packets and ca->delay_min would
 * not account for long aggregation delay when TSO packets get bigger.
 * Ideally even with a very small RTT we would like to have at least one
 * TSO packet being sent and received by GRO, and another one in qdisc layer.
 * We apply another 100% factor because @rate is doubled at this point.
 * We cap the cushion to 1ms.
 */
static u32 hystart_ack_delay(struct sock *sk)
{
	unsigned long rate;

	rate = READ_ONCE(sk->sk_pacing_rate);
	if (!rate)
		return 0;
	return min_t(u64, USEC_PER_MSEC,
		     div64_ul((u64)GSO_MAX_SIZE * 4 * USEC_PER_SEC, rate));
}

static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct linear *ca = inet_csk_ca(sk);
	u32 threshold;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = linear_clock_us(sk);

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta_us) {
			ca->last_ack = now;

			threshold = ca->delay_min + hystart_ack_delay(sk);

			/* Hystart ack train triggers if we get ack past
			 * ca->delay_min/2.
			 * Pacing might have delayed packets up to RTT/2
			 * during slow start.
			 */
			if (sk->sk_pacing_status == SK_PACING_NONE)
				threshold >>= 1;

			if ((s32)(now - ca->round_start) > threshold) {
				ca->found = 1;
				pr_debug("hystart_ack_train (%u > %u) delay_min %u (+ ack_delay %u) cwnd %u\n",
					 now - ca->round_start, threshold,
					 ca->delay_min, hystart_ack_delay(sk), tp->snd_cwnd);
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTTRAINCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}

	if (hystart_detect & HYSTART_DELAY) {
		/* obtain the minimum delay of more than sampling packets */
		if (ca->curr_rtt > delay)
			ca->curr_rtt = delay;
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			ca->sample_cnt++;
		} else {
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min >> 3)) {
				ca->found = 1;
				NET_INC_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS(sock_net(sk),
					      LINUX_MIB_TCPHYSTARTDELAYCWND,
					      tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd;
			}
		}
	}
}

static void linear_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct linear *ca = inet_csk_ca(sk);
	u32 delay;

	/* Some calls are for duplicates without timetamps */
	if (sample->rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_jiffies32 - ca->epoch_start) < HZ)
		return;

	delay = sample->rtt_us;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (!ca->found && tcp_in_slow_start(tp) && hystart &&
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);
}

static struct tcp_congestion_ops linearAtcp __read_mostly = {
	.init		= linearA_init,
	.ssthresh	= linear_recalc_ssthresh,
	.cong_avoid	= linear_cong_avoid,
	.set_state	= linear_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= linear_cwnd_event,
	.pkts_acked     = linear_acked,
	.owner		= THIS_MODULE,
	.name		= "linear-a",
};

static struct tcp_congestion_ops linearBtcp __read_mostly = {
	.init		= linearB_init,
	.ssthresh	= linear_recalc_ssthresh,
	.cong_avoid	= linear_cong_avoid,
	.set_state	= linear_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= linear_cwnd_event,
	.pkts_acked     = linear_acked,
	.owner		= THIS_MODULE,
	.name		= "linear-b",
};

static struct tcp_congestion_ops linearCtcp __read_mostly = {
	.init		= linearC_init,
	.ssthresh	= linear_recalc_ssthresh,
	.cong_avoid	= linear_cong_avoid,
	.set_state	= linear_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= linear_cwnd_event,
	.pkts_acked     = linear_acked,
	.owner		= THIS_MODULE,
	.name		= "linear-c",
};

static int __init lineartcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct linear) > ICSK_CA_PRIV_SIZE);

	tcp_register_congestion_control(&linearCtcp);
	tcp_register_congestion_control(&linearBtcp);
	return tcp_register_congestion_control(&linearAtcp);
}

static void __exit lineartcp_unregister(void)
{
	tcp_unregister_congestion_control(&linearAtcp);
	tcp_unregister_congestion_control(&linearBtcp);
	tcp_unregister_congestion_control(&linearCtcp);
}

module_init(lineartcp_register);
module_exit(lineartcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger, Jonathan Morton");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LINEAR TCP");
MODULE_VERSION("2.3");
