/* NewReno TCP congestion control, modified for SCE support.
 *
 * This version was extensively modified to add SCE support and
 * generally improve its performance and compatibility on real networks.
 *
 *	Jonathan Morton <chromatix99@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>

struct dctcp {
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 next_seq;

	s32 snd_cwnd_cnt;
	u32 loss_cwnd;
	u32 recent_sce;
	u32 sqrt_cwnd;
};

static void reno_sce_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	ca->prior_snd_una = tp->snd_una;
	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->next_seq = tp->snd_nxt;

	ca->snd_cwnd_cnt = 0;
	ca->loss_cwnd = 0;
	ca->recent_sce = 0;
	ca->sqrt_cwnd = 1;
}

static u32 reno_sce_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);

	return max(tp->snd_ssthresh, max(ca->loss_cwnd >> 1U, 2U));
}

static void reno_sce_handle_ack(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;
	u32 mss = inet_csk(sk)->icsk_ack.rcv_mss;
	s32 cnt_over = mss * tp->snd_cwnd;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = mss;
	if (acked_bytes) {
		ca->prior_snd_una = tp->snd_una;

		if ((flags & (CA_ACK_ECE|CA_ACK_ESCE)) == CA_ACK_ESCE) {
			/* Respond to SCE feedback. */
			/* SCE response: pro-rata sqrt(cwnd) */
			u32 scaled_ack = acked_bytes * ca->sqrt_cwnd;

			ca->snd_cwnd_cnt -= scaled_ack;
			ca->loss_cwnd     = tp->snd_cwnd;
			tp->snd_ssthresh  = reno_sce_ssthresh(sk);

			ca->recent_sce    = tp->snd_cwnd + 1;
		} else if(!tcp_in_slow_start(tp) && tcp_is_cwnd_limited(sk)) {
			/* Reno linear growth */
			ca->snd_cwnd_cnt += acked_bytes;
			ca->loss_cwnd = max(ca->loss_cwnd, tp->snd_cwnd);
		}

		/* underflow of counter -> shrink cwnd */
		while(ca->snd_cwnd_cnt <= -cnt_over) {
			ca->snd_cwnd_cnt += cnt_over;
			if(tp->snd_cwnd > 2) {
				tp->snd_cwnd--;
				if(ca->sqrt_cwnd * ca->sqrt_cwnd >= tp->snd_cwnd)
					ca->sqrt_cwnd--;
			}
		}

		/* overflow of counter -> grow cwnd */
		while(ca->snd_cwnd_cnt >= cnt_over) {
			ca->snd_cwnd_cnt -= cnt_over;
			if(tp->snd_cwnd < tp->snd_cwnd_clamp) {
				tp->snd_cwnd++;
				if(ca->sqrt_cwnd * ca->sqrt_cwnd < tp->snd_cwnd)
					ca->sqrt_cwnd++;
			}
		}

		if(ca->recent_sce)
			ca->recent_sce--;
	}
}

static void reno_sce_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp    *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		ca->snd_cwnd_cnt += acked * inet_csk(sk)->icsk_ack.rcv_mss;
	}

	/* if not in slow-start, cwnd evolution governed by ack handler */
}

static void reno_sce_react_to_loss(struct sock *sk, u32 logdiv)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dctcp    *ca = inet_csk_ca(sk);

	ca->loss_cwnd    = tp->snd_cwnd;
	ca->snd_cwnd_cnt = 0;
	tp->snd_cwnd     = max(tp->snd_cwnd - max(tp->snd_cwnd >> logdiv, 1U), 2U);
	tp->snd_ssthresh = ca->loss_cwnd >> 1;

	while(ca->sqrt_cwnd * ca->sqrt_cwnd >= tp->snd_cwnd)
		ca->sqrt_cwnd--;
}

static void reno_sce_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct dctcp    *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_COMPLETE_CWR:
		// ABE 75%, or 87.5% with SCE
		reno_sce_react_to_loss(sk, ca->recent_sce ? 3 : 2);
		break;
	case CA_EVENT_LOSS:
		// loss 50%
		reno_sce_react_to_loss(sk, 1);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static size_t reno_sce_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_DCTCPINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->dctcp, 0, sizeof(info->dctcp));

		info->dctcp.dctcp_enabled = 1;
		info->dctcp.dctcp_ce_state = ca->recent_sce;
		info->dctcp.dctcp_alpha = 0;
		info->dctcp.dctcp_ab_ecn = 0;
		info->dctcp.dctcp_ab_tot = 0;

		*attr = INET_DIAG_DCTCPINFO;
		return sizeof(info->dctcp);
	}
	return 0;
}

static u32 reno_sce_cwnd_undo(struct sock *sk)
{
	const struct dctcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static struct tcp_congestion_ops dctcp __read_mostly = {
	.init		= reno_sce_init,
	.in_ack_event   = reno_sce_handle_ack,
	.cwnd_event	= reno_sce_cwnd_event,
	.ssthresh	= reno_sce_ssthresh,
	.cong_avoid	= reno_sce_cong_avoid,
	.undo_cwnd	= reno_sce_cwnd_undo,
	.get_info	= reno_sce_get_info,
	.owner		= THIS_MODULE,
	.name		= "reno-sce",
};

static int __init reno_sce_register(void)
{
	BUILD_BUG_ON(sizeof(struct dctcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&dctcp);
}

static void __exit reno_sce_unregister(void)
{
	tcp_unregister_congestion_control(&dctcp);
}

module_init(reno_sce_register);
module_exit(reno_sce_unregister);

MODULE_AUTHOR("Jonathan Morton <chromatix99@gmail.com>");

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("NewReno TCP with SCE (Reno-SCE)");
