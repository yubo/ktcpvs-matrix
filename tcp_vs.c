/*
 * KTCPVS       An implementation of the TCP Virtual Server daemon inside
 *              kernel for the LINUX operating system. KTCPVS can be used
 *              to build a moderately scalable and highly available server
 *              based on a cluster of servers, with more flexibility.
 *
 * Version:     $Id: tcp_vs.c,v 1.15.2.3 2004/12/17 17:39:48 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include "tcp_vs.h"
MODULE_LICENSE("GPL");

#define __KERNEL_SYSCALLS__	/*  for waitpid */

#define RH_NPTL_KLUDGE

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/gfp.h>
#include <asm/unistd.h>

#include <linux/delay.h>

#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>

/* wrapper for waitpid in kernel mode */
_syscall3(int, waitpid, pid_t, pid, int __user *, stat_addr, int, options)



static int errno;

static atomic_t tcp_vs_daemon_count = ATOMIC_INIT(0);


EXPORT_SYMBOL(register_tcp_vs_scheduler);
EXPORT_SYMBOL(unregister_tcp_vs_scheduler);
EXPORT_SYMBOL(tcp_vs_connect2dest);
EXPORT_SYMBOL(tcp_vs_sendbuffer);
EXPORT_SYMBOL(tcp_vs_xmit);
EXPORT_SYMBOL(tcp_vs_recvbuffer);
EXPORT_SYMBOL(tcp_vs_getword);
EXPORT_SYMBOL(tcp_vs_getline);
#ifdef CONFIG_TCP_VS_DEBUG
EXPORT_SYMBOL(tcp_vs_get_debug_level);
#endif
EXPORT_SYMBOL(sysctl_ktcpvs_unload);
EXPORT_SYMBOL(sysctl_ktcpvs_keepalive_timeout);
EXPORT_SYMBOL(sysctl_ktcpvs_read_timeout);
EXPORT_SYMBOL(tcp_vs_srvconn_get);
EXPORT_SYMBOL(tcp_vs_srvconn_put);
EXPORT_SYMBOL(tcp_vs_srvconn_new);
EXPORT_SYMBOL(tcp_vs_srvconn_free);
EXPORT_SYMBOL(tcp_vs_add_slowtimer);
EXPORT_SYMBOL(tcp_vs_del_slowtimer);
EXPORT_SYMBOL(tcp_vs_mod_slowtimer);


struct tcp_vs_conn *
tcp_vs_conn_create(struct socket *sock, char *buffer, size_t buflen)
{
	struct tcp_vs_conn *conn;

	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn) {
		TCP_VS_ERR("create_conn no memory available\n");
		return NULL;
	}
	memset(conn, 0, sizeof(*conn));

	/* clone the socket */
	conn->csock = sock_alloc();
	if (!conn->csock) {
		kfree(conn);
		return NULL;
	}

	conn->csock->type = sock->type;
	conn->csock->ops = sock->ops;

	conn->buffer = buffer;
	conn->buflen = buflen;

	/* we probably need assign conn->addr here!!! */

	return conn;
}


int
tcp_vs_conn_release(struct tcp_vs_conn *conn)
{
	/* release the cloned socket */
	sock_release(conn->csock);

	if (conn->dest)
		atomic_dec(&conn->dest->conns);

	kfree(conn);

	return 0;
}


/*
 *	Relay data from one socket to the other
 *
 *	Make sure that data is available at "from" before calling it.
 */

static int
skb_send_datagram_socket(const struct sk_buff *skb, struct socket *to)
{
	int written, i;
	struct sk_buff *list;
	int res;

	if (!skb_is_nonlinear(skb))
		return tcp_vs_sendbuffer(to, skb->data, skb->len, 0);

	res = tcp_vs_sendbuffer(to, skb->data, skb_headlen(skb), MSG_MORE);
	if (res < 0)
		return res;
	written = res;

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		char *vaddr;
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		struct page *page = frag->page;

		vaddr = kmap(page);
		res = tcp_vs_sendbuffer(to, vaddr + frag->page_offset,
					frag->size, 0);
		if (res < 0)
			goto out;
		written += res;
		kunmap(page);
	}

	for (list = skb_shinfo(skb)->frag_list; list; list = list->next) {
		res = skb_send_datagram_socket(list, to);
		if (res < 0)
			goto out;
		written += res;
	}
      out:
	return written;
}


static inline void
skb_entail(struct sock *sk, struct tcp_opt *tp, struct sk_buff *skb)
{
	skb->csum = 0;
	TCP_SKB_CB(skb)->seq = tp->write_seq;
	TCP_SKB_CB(skb)->end_seq = tp->write_seq;
	TCP_SKB_CB(skb)->flags = TCPCB_FLAG_ACK;
	TCP_SKB_CB(skb)->sacked = 0;
	__skb_queue_tail(&sk->sk_write_queue, skb);

	/* not sure that it is enough for forward_alloc, we'll see */
	if (sk->sk_forward_alloc < skb->truesize) {
		/*  tcp_mem_schedule(sk, skb->truesize, 0); */
#define TCP_PAGES(amt) (((amt)+SK_STREAM_MEM_QUANTUM-1)/SK_STREAM_MEM_QUANTUM)
		int pages = TCP_PAGES(skb->truesize);
		sk->sk_forward_alloc += pages * SK_STREAM_MEM_QUANTUM;
	}
	sk_charge_skb(sk, skb);

	if (sk->sk_send_head == NULL)
		sk->sk_send_head = skb;
}

static int
tcp_vs_relay_socket(struct socket *from, struct socket *to)
{
	struct sk_buff *skb;
	int len;
	struct sock *sk;
	struct tcp_opt *tp;

	lock_sock(from->sk);
	skb = skb_dequeue(&from->sk->sk_receive_queue);
	if (!skb) {
		release_sock(from->sk);
		return -1;
	}

	len = skb->len;
	if (len == 0) {
		kfree_skb(skb);
		release_sock(from->sk);
		return 0;
	}
	release_sock(from->sk);

	if (!sysctl_ktcpvs_zerocopy_send) {
		int res;
		int written;

		res = skb_send_datagram_socket(skb, to);
		if (res < 0)
			return res;
		written = res;
		if (written != len) {
			if (skb_is_nonlinear(skb) &&
			    skb_linearize(skb, GFP_ATOMIC) != 0) {
				TCP_VS_ERR_RL("relay socket data error "
					      "(len=%d, written=%d).\n",
					      len, written);
				kfree_skb(skb);
				return written;
			}
		      sendagain:
			res = tcp_vs_sendbuffer(to, skb->data + written,
						skb->len - written, 0);
			if (res < 0) {
				kfree_skb(skb);
				return written;
			}

			written += res;
			if (written != len)
				goto sendagain;
		}
		kfree_skb(skb);
		return written;
	}

	/* we cannot release the skb here, but we do need to call
	   its destructor so that the sock_rfree can update the
	   source sk->rmem_alloc correctly. */
	if (skb->destructor) {
		skb->destructor(skb);
	}

	/* drop old route */
	dst_release(skb->dst);
	skb->dst = NULL;
#ifdef CONFIG_NETFILTER_DEBUG
	skb->nf_debug = 0;
#endif				/* CONFIG_NETFILTER_DEBUG */

	sk = to->sk;
	tp = tcp_sk(sk);

	lock_sock(sk);

	/* set the owner of skb to the dest sk */
	skb_set_owner_w(skb, sk);
	skb_entail(sk, tp, skb);

	skb->ip_summed = CHECKSUM_HW;
	tp->write_seq += len;
	TCP_SKB_CB(skb)->end_seq += len;

	tcp_push_pending_frames(sk, tp);
	release_sock(sk);

	return len;
}


/*
 *   Handle TCP connection between client and the tcpvs, and the one
 *   between the tcpvs and the selected server. Terminate until that
 *   the two connections are done.
 */
int
tcp_vs_conn_handle(struct tcp_vs_conn *conn, struct tcp_vs_service *svc)
{
	struct socket *csock, *dsock;
	DECLARE_WAITQUEUE(wait1, current);
	DECLARE_WAITQUEUE(wait2, current);
	unsigned long lastupdated;

	EnterFunction(5);

	csock = conn->csock;
	if (csock->sk->sk_state != TCP_ESTABLISHED) {
		if (csock->sk->sk_state == TCP_CLOSE_WAIT)
			return 0;
		TCP_VS_ERR("Error connection not established (state %d)\n",
			   csock->sk->sk_state);
		return -1;
	}

	/*
	   call its scheduler to process the connect request, the scheduler may:
	   1, Select a destination server and return 0, or;
	   2, Deal with the requestion alone and return 1, or;
	   3, Return -1  when could not find a right server
	   4, return -2 when other errors such as socket broken occur.
	 */
	switch (svc->scheduler->schedule(conn, svc)) {
	case 1:		/* scheduler has done all the work */
		return 0;

	case 0:		/* further process needed */
		break;
	case -1:		/* try to redirect the connection to other sockets */

		/* fault tolerance  function*/
		if (!fault_redirect(conn,svc))
			break;

		if (svc->conf.redirect_port) {
			redirect_to_local(conn, svc->conf.redirect_addr,
					  svc->conf.redirect_port);
			return 0;
		}
		TCP_VS_ERR("no destination available\n");
		return -1;
	default:
		return 0;
	}

	dsock = conn->dsock;
	if (dsock == NULL) {
		TCP_VS_ERR("dsock is NULL,is there bugs?\n");
		return 0;
	}

	/*
	 *  NOTE: we should add a mechanism to provide higher degree of
	 *        fault-tolerance here in the future, if the destination
	 *        server is dead, we need replay the request to a
	 *        surviving one, and continue to provide the service to
	 *        the established connection.
	 *        Transaction and Logging?
	 *        We need to explore.
	 */

	lastupdated = jiffies;

	while ((jiffies - lastupdated) < sysctl_ktcpvs_read_timeout * HZ) {
		/* if the connection is closed, go out of this loop */
		if (dsock->sk->sk_state != TCP_ESTABLISHED
		    && dsock->sk->sk_state != TCP_CLOSE_WAIT)
			break;

		if (csock->sk->sk_state != TCP_ESTABLISHED
		    && csock->sk->sk_state != TCP_CLOSE_WAIT)
			break;

		/* Do we have data from server? */
		if (!skb_queue_empty(&(dsock->sk->sk_receive_queue))) {
			if (tcp_vs_relay_socket(dsock, csock) == 0)
				break;
			lastupdated = jiffies;
		}

		/* Do we have data from client? */
		if (!skb_queue_empty(&(csock->sk->sk_receive_queue))) {
			if (tcp_vs_relay_socket(csock, dsock) == 0)
				break;
			lastupdated = jiffies;
		}

		if (skb_queue_empty(&(dsock->sk->sk_receive_queue))
		    && skb_queue_empty(&(csock->sk->sk_receive_queue))) {
			if (dsock->sk->sk_state == TCP_CLOSE_WAIT
			    || csock->sk->sk_state == TCP_CLOSE_WAIT)
				break;

			/*
			 *  Put the current task on the sleep wait queue
			 *  of both the sockets, wake up the task if one
			 *  socket has some data ready.
			 */
			add_wait_queue(csock->sk->sk_sleep, &wait1);
			add_wait_queue(dsock->sk->sk_sleep, &wait2);
			__set_current_state(TASK_INTERRUPTIBLE);

			schedule_timeout(HZ);

			__set_current_state(TASK_RUNNING);
			remove_wait_queue(csock->sk->sk_sleep, &wait1);
			remove_wait_queue(dsock->sk->sk_sleep, &wait2);
		}
	}

	/* close the socket to the destination */
	sock_release(dsock);

	LeaveFunction(5);
	return 0;
}


enum {
	SERVER_DEAD = 0,
	SERVER_STARTING,
	SERVER_READY,
	SERVER_BUSY
};

#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE	32
#endif

struct tcp_vs_child_table {
	struct tcp_vs_child children[KTCPVS_CHILD_HARD_LIMIT];
	int max_daemons_limit;
	int idle_spawn_rate;
	unsigned long last_modified;	/* last time of add/killing child */
};

static int tcp_vs_child(void *__child);

static inline void
make_child(struct tcp_vs_child_table *tbl,
	   int slot, struct tcp_vs_service *svc)
{
	if (slot + 1 > tbl->max_daemons_limit)
		tbl->max_daemons_limit = slot + 1;
	tbl->last_modified = jiffies;
	tbl->children[slot].svc = svc;
	if (kernel_thread(tcp_vs_child, &tbl->children[slot],
			  CLONE_VM | CLONE_FS | CLONE_FILES) < 0)
		TCP_VS_ERR("spawn child failed\n");
}

static inline void
kill_child(struct tcp_vs_child_table *tbl, int slot)
{
	kill_proc(tbl->children[slot].pid, SIGKILL, 1);
	tbl->last_modified = jiffies;
}

static inline void
update_child_status(struct tcp_vs_child *chd, __u16 status)
{
	chd->status = status;
}

static inline void
child_pool_maintenance(struct tcp_vs_child_table *tbl,
		       struct tcp_vs_service *svc)
{
	int i;
	int free_slots[MAX_SPAWN_RATE];
	int free_length = 0;
	int to_kill = -1;
	int idle_count = 0;
	int last_non_dead = -1;

	for (i = 0; i < svc->conf.maxClients; i++) {
		int status;

		if (i >= tbl->max_daemons_limit
		    && free_length == tbl->idle_spawn_rate) break;
		status = tbl->children[i].status;
		switch (status) {
		case SERVER_DEAD:
			if (free_length < tbl->idle_spawn_rate) {
				free_slots[free_length] = i;
				free_length++;
			}
			break;
		case SERVER_STARTING:
			idle_count++;
			last_non_dead = i;
			break;
		case SERVER_READY:
			idle_count++;
			to_kill = i;
			last_non_dead = i;
			break;
		case SERVER_BUSY:
			last_non_dead = i;
			break;
		}
	}
	tbl->max_daemons_limit = last_non_dead + 1;

	if (idle_count > svc->conf.maxSpareServers) {
		/* kill one child each time */
		kill_child(tbl, to_kill);
		tbl->idle_spawn_rate = 1;
	} else if (idle_count < svc->conf.minSpareServers) {
		if (free_length) {
			if (tbl->idle_spawn_rate > 8 && net_ratelimit())
				TCP_VS_INFO
				    ("Server %s seems busy, you may "
				     "need to increase StartServers, "
				     "or Min/MaxSpareServers\n",
				     svc->ident.name);
			/* spawn a batch of children */
			for (i = 0; i < free_length; i++)
				make_child(tbl, free_slots[i], svc);

			if (tbl->idle_spawn_rate < MAX_SPAWN_RATE)
				tbl->idle_spawn_rate *= 2;
		} else if (net_ratelimit())
			TCP_VS_INFO
			    ("Server %s reached MaxClients setting, "
			     "consider raising the MaxClients "
			     "setting\n", svc->ident.name);
	} else {
		/* if the number of spare servers remains in the interval
		   (minSpareServers, maxSpareServers] and the time of
		   last modified is larger than ten minutes, we try to
		   kill one spare child in order to release some resource. */
		if (idle_count > svc->conf.minSpareServers
		    && jiffies - tbl->last_modified > 600 * HZ)
			kill_child(tbl, to_kill);
		tbl->idle_spawn_rate = 1;
	}
}


static int
tcp_vs_child(void *__child)
{
	struct tcp_vs_conn *conn;
	struct socket *sock;
	int ret = 0;
	char *Buffer;
	size_t BufLen;
	struct tcp_vs_child *chd = (struct tcp_vs_child *) __child;
	struct tcp_vs_service *svc = chd->svc;
	

	/* DECLARE_WAIT_QUEUE_HEAD(queue); */
	DECLARE_WAITQUEUE(wait, current);

	EnterFunction(3);

	atomic_inc(&svc->childcount);
	chd->pid = current->pid;
	update_child_status(chd, SERVER_STARTING);

	snprintf(current->comm, sizeof(current->comm),
		 "ktcpvs %s c", svc->ident.name);
	lock_kernel();
	daemonize(C_THREAD_NAME);

	/* Block all signals except SIGKILL and SIGSTOP */
#ifdef RH_NPTL_KLUDGE
	spin_lock_irq(&current->sighand->siglock);
#else
	spin_lock_irq(&current->sigmask_lock);
#endif
	siginitsetinv(&current->blocked,
		      sigmask(SIGKILL) | sigmask(SIGSTOP));
#ifdef RH_NPTL_KLUDGE
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
#else
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
#endif

	sock = svc->mainsock;
	if (sock == NULL) {
		TCP_VS_ERR("%s's socket is NULL\n", svc->ident.name);
		ret = -1;
		goto out;
	}

	Buffer = (char *) __get_free_page(GFP_KERNEL);
	if (Buffer == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	BufLen = PAGE_SIZE;

	while (svc->stop == 0 && sysctl_ktcpvs_unload == 0) {
		if (signal_pending(current)) {
			TCP_VS_DBG(3, "child (pid=%d): signal received\n",
				   current->pid);
			break;
		}

		update_child_status(chd, SERVER_READY);
		if (tcp_sk(sock->sk)->accept_queue == NULL) {
			/* interruptible_sleep_on_timeout(&queue, HZ); */
			add_wait_queue(sock->sk->sk_sleep, &wait);
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ);
			__set_current_state(TASK_RUNNING);
			remove_wait_queue(sock->sk->sk_sleep, &wait);
			continue;
		}

		/* create tcp_vs_conn object */
		conn = tcp_vs_conn_create(sock, Buffer, BufLen);
		if (!conn)
			break;

		/* Do the actual accept */
		ret = sock->ops->accept(sock, conn->csock, O_NONBLOCK);
		if (ret < 0) {
			tcp_vs_conn_release(conn);
			continue;
		}

		update_child_status(chd, SERVER_BUSY);
		atomic_inc(&svc->conns);

		/* Do the work */
		ret = tcp_vs_conn_handle(conn, svc);
		if (ret < 0) {
			TCP_VS_ERR_RL("Error handling connection\n");
			tcp_vs_conn_release(conn);
			atomic_dec(&svc->conns);
			break;
		};

		/* release tcp_vs_conn */
		tcp_vs_conn_release(conn);
		atomic_dec(&svc->conns);
	}

	TCP_VS_DBG(3,"Try to free buffer page ..\n");
	free_page((unsigned long) Buffer);
      out:
	update_child_status(chd, SERVER_DEAD);
	atomic_dec(&svc->childcount);
	LeaveFunction(3);
	return 0;
}


static int
tcp_vs_daemon(void *__svc)
{
	int waitpid_result;
	int i;
	struct tcp_vs_service *svc = (struct tcp_vs_service *) __svc;
	struct tcp_vs_child_table *child_table = NULL;

	DECLARE_WAIT_QUEUE_HEAD(WQ);

	atomic_inc(&tcp_vs_daemon_count);

	snprintf(current->comm, sizeof(current->comm),
		 "ktcpvs %s d", svc->ident.name);
	lock_kernel();
	daemonize(D_THREAD_NAME);
	EnterFunction(3);

	/* Block all signals except SIGKILL and SIGSTOP */
#ifdef RH_NPTL_KLUDGE
	spin_lock_irq(&current->sighand->siglock);
#else
	spin_lock_irq(&current->sigmask_lock);
#endif
	siginitsetinv(&current->blocked,
		      sigmask(SIGKILL) | sigmask(SIGSTOP));
#ifdef RH_NPTL_KLUDGE
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
#else
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
#endif

	if (!svc->scheduler) {
		TCP_VS_ERR("%s's scheduler is not bound\n",
			   svc->ident.name);
		goto out;
	}

	child_table = vmalloc(sizeof(*child_table));
	if (!child_table)
		goto out;

	/* Then start listening and spawn the daemons */
	if (StartListening(svc) < 0)
		goto out;

	atomic_set(&svc->running, 1);
	atomic_set(&svc->childcount, 0);
	svc->stop = 0;

	memset(child_table, 0, sizeof(*child_table));
	child_table->idle_spawn_rate = 1;

	for (i = 0; i < svc->conf.startservers; i++)
		make_child(child_table, i, svc);

	/* Then wait for deactivation */
	while (svc->stop == 0 && !signal_pending(current)
	       && sysctl_ktcpvs_unload == 0) {
		interruptible_sleep_on_timeout(&WQ, HZ);

		/* dynamically keep enough thread to handle load */
		child_pool_maintenance(child_table, svc);

		/* reap the zombie daemons */
		waitpid_result = waitpid(-1, NULL, __WCLONE | WNOHANG);
		//waitpid_result = 0;
	}

	/* Wait for tcp_vs_child to stop, one second per iteration */
	while (atomic_read(&svc->childcount) > 0)
		interruptible_sleep_on_timeout(&WQ, HZ);

	/* sleep wait for all child terminated */
	msleep(1);

	/* reap the zombie daemons */
	waitpid_result = 1;
	while (waitpid_result > 0)
		waitpid_result = waitpid(-1, NULL, __WCLONE | WNOHANG);

	/* stop listening */
	StopListening(svc);

      out:
	if (child_table) {
		TCP_VS_DBG(8,"Try to freeing child_table ..\n");
		vfree(child_table);
		TCP_VS_DBG(8,"Child table freed.\n");
	}
	svc->start = 0;
	atomic_set(&svc->running, 0);
	atomic_dec(&tcp_vs_daemon_count);
	LeaveFunction(3);

	return 0;
}


static int
master_daemon(void *unused)
{
	int waitpid_result;
	struct list_head *l;
	struct tcp_vs_service *svc;


	DECLARE_WAIT_QUEUE_HEAD(WQ);

	try_module_get(THIS_MODULE);

	sprintf(current->comm, "ktcpvs master");
	lock_kernel();
	daemonize(M_THREAD_NAME);

	/* Block all signals except SIGKILL and SIGSTOP */
#ifdef RH_NPTL_KLUDGE
	spin_lock_irq(&current->sighand->siglock);
#else
	spin_lock_irq(&current->sigmask_lock);
#endif
	siginitsetinv(&current->blocked,
		      sigmask(SIGKILL) | sigmask(SIGSTOP));
#ifdef RH_NPTL_KLUDGE
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
#else
	recalc_sigpending(current);
	spin_unlock_irq(&current->sigmask_lock);
#endif

	/* main loop */
	while (sysctl_ktcpvs_unload == 0) {
		read_lock(&__tcp_vs_svc_lock);
		list_for_each(l, &tcp_vs_svc_list) {
			svc = list_entry(l, struct tcp_vs_service, list);
			if (!atomic_read(&svc->running) && svc->start)
				kernel_thread(tcp_vs_daemon, svc, 0);
		}
		read_unlock(&__tcp_vs_svc_lock);

		/* run the slowtimer collection */
		tcp_vs_slowtimer_collect();

		if (signal_pending(current))
			break;

		current->state = TASK_INTERRUPTIBLE;
		interruptible_sleep_on_timeout(&WQ, HZ);

		/* reap the daemons */
		waitpid_result = waitpid(-1, NULL, __WCLONE | WNOHANG);
	}

	/* Wait for tcp_vs daemons to stop, one second per iteration */
	while (atomic_read(&tcp_vs_daemon_count) > 0)
		interruptible_sleep_on_timeout(&WQ, HZ);

	/* sleep wait for all child terminated */
	msleep(1);

	/* reap the zombie daemons */
	waitpid_result = 1;
	while (waitpid_result > 0)
		waitpid_result = waitpid(-1, NULL, __WCLONE | WNOHANG);

	/* flush all the virtual servers */
	tcp_vs_flush();

	TCP_VS_INFO("The master daemon stopped. "
		    "You can unload the module now.\n");

	module_put(THIS_MODULE);

	return 0;
}


static int __init
ktcpvs_init(void)
{
	tcp_vs_control_start();

	tcp_vs_slowtimer_init();

	tcp_vs_srvconn_init();

	(void) kernel_thread(master_daemon, NULL, 0);

	TCP_VS_INFO("ktcpvs loaded.\n");

	return 0;
}


static void __exit
ktcpvs_cleanup(void)
{
	tcp_vs_srvconn_cleanup();

	tcp_vs_slowtimer_cleanup();

	tcp_vs_control_stop();

	TCP_VS_INFO("ktcpvs unloaded.\n");
}


module_init(ktcpvs_init);
module_exit(ktcpvs_cleanup);
