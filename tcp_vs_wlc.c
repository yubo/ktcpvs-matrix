/*
 * KTCPVS       An implementation of the TCP Virtual Server daemon inside
 *              kernel for the LINUX operating system. KTCPVS can be used
 *              to build a moderately scalable and highly available server
 *              based on a cluster of servers, with more flexibility.
 *
 * Version:     $Id: tcp_vs_wlc.c,v 1.8 2003/05/23 02:08:34 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * tcp_vs_wlc.c: weighted least-connection scheduling
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>

#include "tcp_vs.h"


static int
tcp_vs_wlc_init_svc(struct tcp_vs_service *svc)
{
	return 0;
}


static int
tcp_vs_wlc_done_svc(struct tcp_vs_service *svc)
{
	return 0;
}


static int
tcp_vs_wlc_update_svc(struct tcp_vs_service *svc)
{
	return 0;
}


/*
 *    Weighted Least Connection scheduling
 */
static int
tcp_vs_wlc_schedule(struct tcp_vs_conn *conn, struct tcp_vs_service *svc)
{
	register struct list_head *l, *e;
	tcp_vs_dest_t *dest, *least;

	TCP_VS_DBG(5, "tcp_vs_wlc_schedule(): Scheduling...\n");

	/*
	 * We use the following formula to estimate the overhead:
	 *                dest->conns / dest->weight
	 *
	 * Remember -- no floats in kernel mode!!!
	 * The comparison of h1*w2 > h2*w1 is equivalent to that of
	 *                h1/w1 > h2/w2
	 * when each weight is larger than zero.
	 *
	 * The server with weight=0 is quiesced and will not receive any
	 * new connection.
	 */

	read_lock(&svc->lock);
	l = &svc->destinations;
	for (e = l->next; e != l; e = e->next) {
		least = list_entry(e, tcp_vs_dest_t, n_list);
		if (least->weight > 0) {
			goto nextstage;
		}
	}
	read_unlock(&svc->lock);
	return -1;

	/*
	 *    Find the destination with the least load.
	 */
      nextstage:
	for (e = e->next; e != l; e = e->next) {
		dest = list_entry(e, tcp_vs_dest_t, n_list);
		if (atomic_read(&least->conns) * dest->weight
		    > atomic_read(&dest->conns) * least->weight) {
			least = dest;
		}
	}
	read_unlock(&svc->lock);

	TCP_VS_DBG(5, "WLC: server %d.%d.%d.%d:%d "
		   "conns %d refcnt %d weight %d\n",
		   NIPQUAD(least->addr), ntohs(least->port),
		   atomic_read(&least->conns),
		   atomic_read(&least->refcnt), least->weight);

	conn->dsock = tcp_vs_connect2dest(least);
	if (!conn->dsock) {
		TCP_VS_ERR_RL("The destination is not available\n");
		return -1;
	}
	atomic_inc(&least->conns);
	conn->dest = least;

	return 0;
}


static struct tcp_vs_scheduler tcp_vs_wlc_scheduler = {
	{0},			/* n_list */
	"wlc",			/* name */
	THIS_MODULE,		/* this module */
	tcp_vs_wlc_init_svc,	/* initializer */
	tcp_vs_wlc_done_svc,	/* done */
	tcp_vs_wlc_update_svc,	/* update */
	tcp_vs_wlc_schedule,	/* select a server from the destination list */
};


static int __init
tcp_vs_wlc_init(void)
{
	INIT_LIST_HEAD(&tcp_vs_wlc_scheduler.n_list);
	return register_tcp_vs_scheduler(&tcp_vs_wlc_scheduler);
}

static void __exit
tcp_vs_wlc_cleanup(void)
{
	unregister_tcp_vs_scheduler(&tcp_vs_wlc_scheduler);
}

module_init(tcp_vs_wlc_init);
module_exit(tcp_vs_wlc_cleanup);
MODULE_LICENSE("GPL");
