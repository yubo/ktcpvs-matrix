/*
 * KTCPVS       An implementation of the TCP Virtual Server daemon inside
 *              kernel for the LINUX operating system. KTCPVS can be used
 *              to build a moderately scalable and highly available server
 *              based on a cluster of servers, with more flexibility.
 *
 * redirect.c: redirect requests to other server sockets
 *
 * Version:     $Id: redirect.c,v 1.2 2003/05/23 02:08:34 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/tcp.h>

#include "tcp_vs.h"

/* Note: most code of redirecting to local socket is taken from TUX */

static void
dummy_destructor(struct open_request *req)
{
}

static struct or_calltable dummy = {
	0,
	NULL,
	NULL,
	&dummy_destructor,
	NULL
};


int
redirect_to_local(struct tcp_vs_conn *conn, __u32 addr, __u16 port)
{
	struct socket *sock;
	struct open_request *tcpreq;
	struct sock *sk, *oldsk;

	struct tcp_opt *tp;
	int rc = 0;

	sock = conn->csock;

	/* search for local listening user-space socket */
	local_bh_disable();
	sk = tcp_v4_lookup_listener(addr, ntohs(port), 0);
	local_bh_enable();

	/* No socket found */
	if (!sk) {
		TCP_VS_ERR_RL("no server found\n");
		rc = -1;
		goto out;
	}

	oldsk = sock->sk;
	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		rc = -1;
		goto out_unlock;
	}

	tcpreq = tcp_openreq_alloc();
	if (!tcpreq) {
		rc = -1;
		goto out_unlock;
	}

	sock->sk = NULL;
	sock->state = SS_UNCONNECTED;

	tcpreq->class = &dummy;
	write_lock_irq(&oldsk->sk_callback_lock);
	oldsk->sk_socket = NULL;
	oldsk->sk_sleep = NULL;
	write_unlock_irq(&oldsk->sk_callback_lock);

	tcp_acceptq_queue(sk, tcpreq, oldsk);

	tp = sk->sk_protinfo;
	tp->nonagle = 0;
	sk->sk_data_ready(sk, 0);

      out_unlock:
	release_sock(sk);
	sock_put(sk);
      out:
	return rc;
}
