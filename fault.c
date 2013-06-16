
/*
 *
 * fault.c:     Fault tolerence support for ktcpvs, distribute the connection to one
 * 		active server when the sheduler	can't get a connection
 *
 * Version:     
 *
 * Author:     Wenming Zhang <zhwenming@gmail.com>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/ctype.h>

#include <linux/skbuff.h>
#include <net/sock.h>

#include <linux/gfp.h>
#include <linux/tcp.h>

#include "tcp_vs.h"
#include "tcp_vs_http_parser.h"
#include "tcp_vs_http_trans.h"

static inline tcp_vs_dest_t *
__first_active_schedule(struct list_head *destinations)
{
	register struct list_head *e;
	tcp_vs_dest_t *dest;

	list_for_each(e, destinations) {
		dest = list_entry(e, tcp_vs_dest_t, r_list);
		if ( dest->active ) 
			return dest;
	}
	return NULL;

}

static tcp_vs_dest_t *
active_dest_get(struct tcp_vs_service *svc)
{
	struct list_head *l;
	struct tcp_vs_rule *r;
	tcp_vs_dest_t *dest = NULL;

	read_lock(&svc->lock);
	list_for_each(l, &svc->rule_list) {
		r = list_entry(l, struct tcp_vs_rule, list);
		dest =
		    __first_active_schedule(&r->destinations);
		if ( dest ) 
			break;
	}
	read_unlock(&svc->lock);

	return dest;
}


/*
 */
int
fault_redirect(struct tcp_vs_conn *conn, struct tcp_vs_service *svc)
{
	tcp_vs_dest_t *dest;
	struct socket *dsock;

	EnterFunction(6);


	dest = active_dest_get(svc);
	if (!dest) {
		TCP_VS_ERR_RL("Can't get active dest server!\n");
		return -1;
	}

	TCP_VS_DBG(5, "HTTP: server %d.%d.%d.%d:%d "
		   "conns %d refcnt %d weight %d\n",
		   NIPQUAD(dest->addr), ntohs(dest->port),
		   atomic_read(&dest->conns),
		   atomic_read(&dest->refcnt), dest->weight);

	dsock = tcp_vs_connect2dest(dest);
	if (!dsock) {
		TCP_VS_ERR_RL("The destination is not available\n");
		return -1;
	}

	atomic_inc(&dest->conns);
	conn->dest = dest;
	conn->dsock = dsock;

	LeaveFunction(6);

	return 0;
}
