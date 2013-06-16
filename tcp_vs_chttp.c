/*
 * KTCPVS       An implementation of the TCP Virtual Server daemon inside
 *              kernel for the LINUX operating system. KTCPVS can be used
 *              to build a moderately scalable and highly available server
 *              based on a cluster of servers, with more flexibility.
 *
 * tcp_vs_chttp.c: KTCPVS content-based scheduling module for HTTP service
 *		   with cookie support.
 *
 * Version:	$Id: tcp_vs_chttp.c,v 1.7 2003/06/14 16:09:47 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *              Hai Long <david_lung@yahoo.com>
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

// for 2.6 kernel
#include <linux/tcp.h>
#include "tcp_vs.h"
#include "tcp_vs_http_parser.h"
#include "tcp_vs_http_trans.h"
#include "avl.h"


#define COOKIE_DISCARD_TIME	600

/* cookie table entry definition */
typedef struct cookie_entry_s {
	cookie_key_t *key;
	slowtimer_t cookie_expire_timer;
} cookie_entry_t;

/* session table entry definition */
typedef struct session_entry_s {
	ulong sid;
	struct tcp_vs_dest *dest;
	unsigned int ref_cnt;
} session_entry_t;

/* lock for session id */
static spinlock_t session_id_lock = SPIN_LOCK_UNLOCKED;

static ulong ktcpvs_session_id = 1;

/* lock for the cook & session table */
static spinlock_t avl_tbl_lock = SPIN_LOCK_UNLOCKED;

/* cookie table */
static struct avl_table *cookie_tbl = NULL;

/* session table */
static struct avl_table *session_tbl = NULL;

static int
tcp_vs_chttp_init_svc(struct tcp_vs_service *svc)
{
	return 0;
}

static int
tcp_vs_chttp_done_svc(struct tcp_vs_service *svc)
{
	return 0;
}

static int
tcp_vs_chttp_update_svc(struct tcp_vs_service *svc)
{
	return 0;
}

static inline struct tcp_vs_dest *
__tcp_vs_chttp_wlc_schedule(struct list_head *destinations)
{
	register struct list_head *e;
	struct tcp_vs_dest *dest, *least;

	list_for_each(e, destinations) {
		least = list_entry(e, struct tcp_vs_dest, r_list);

		if (least->weight > 0) {
			goto nextstage;
		}
	}
	return NULL;

	/*
	 *      Find the destination with the least load.
	 */
      nextstage:
	for (e = e->next; e != destinations; e = e->next) {
		dest = list_entry(e, struct tcp_vs_dest, r_list);

		if (atomic_read(&least->conns) * dest->weight >
		    atomic_read(&dest->conns) * least->weight) {
			least = dest;
		}
	}

	return least;
}


static struct tcp_vs_dest *
tcp_vs_chttp_matchrule(struct tcp_vs_service *svc, http_request_t * req)
{
	struct list_head *l;
	struct tcp_vs_rule *r;
	struct tcp_vs_dest *dest = NULL;
	char *uri;

	if (!(uri = kmalloc(req->uri_len + 1, GFP_KERNEL))) {
		TCP_VS_ERR("No memory!\n");
		return NULL;
	}
	memcpy(uri, req->uri_str, req->uri_len);
	uri[req->uri_len] = '\0';
	TCP_VS_DBG(5, "matching request URI: %s\n", uri);

	read_lock(&svc->lock);
	list_for_each(l, &svc->rule_list) {
		r = list_entry(l, struct tcp_vs_rule, list);
		if (!regexec(&r->rx, uri, 0, NULL, 0)) {
			/* HIT */
			dest =
			    __tcp_vs_chttp_wlc_schedule(&r->destinations);
			break;
		}
	}
	read_unlock(&svc->lock);

	kfree(uri);
	return dest;
}


/****************************************************************************
*  Inject a cookie with a unique session id to the http client.
*
*/
static ulong
inject_session_id_cookie(struct socket *sock, int set_cookie2)
{
	char buf[80];		/* avoid kmalloc */
	ulong id;

	spin_lock(&session_id_lock);
	id = ktcpvs_session_id++;
	spin_unlock(&session_id_lock);

	if (set_cookie2) {
		sprintf(buf,
			"Set-Cookie2:KTCPVS_SID=%ld; Version=1; Path=/%c%c",
			id, CR, LF);
	} else {
		sprintf(buf, "Set-Cookie:KTCPVS_SID=%ld; Path=/%c%c", id,
			CR, LF);

	}

	if (tcp_vs_xmit(sock, buf, strlen(buf), MSG_MORE) < 0) {
		TCP_VS_ERR("Error in injecting session id.\n");
	}

	return id;
}


/****************************************************************************
*
*	comparator for cookie table (AVL tree)
*	Key = <sid, cookie_name>
*/
static int
compare_cookie_entry(const void *avl_a, const void *avl_b, void *avl_param)
{
	cookie_key_t *cookie_a, *cookie_b;
	int ret;

	cookie_a = ((cookie_entry_t *) avl_a)->key;
	cookie_b = ((cookie_entry_t *) avl_b)->key;

	ret = cookie_a->sid - cookie_b->sid;
	if (ret == 0) {
		ret = strcmp(cookie_a->name, cookie_b->name);
	}

	return ret;
}


/****************************************************************************
*
*	comparator for session table (AVL tree)
*	Key = <sid>
*/
static int
compare_session_entry(const void *avl_a, const void *avl_b,
		      void *avl_param)
{
	ulong a, b;

	a = ((session_entry_t *) avl_a)->sid;
	b = ((session_entry_t *) avl_b)->sid;

	return (a - b);
}


/****************************************************************************
*
*	Free the cookie list
*/
static void
free_cookie_list(struct list_head *cookie_list)
{
	struct list_head *l, *tmp;
	http_cookie_t *cookie;

	list_for_each_safe(l, tmp, cookie_list) {
		list_del(l);
		cookie = list_entry(l, http_cookie_t, c_list);

		/* free this cookie */
		if (cookie->key != NULL) {
			kfree(cookie->key->name);
			kfree(cookie->key);
		}
		kfree(cookie);
	}
}


/****************************************************************************
*
*    search session table to find a destination server according to session id.
*
*/
static struct tcp_vs_dest *
find_server_by_session_id(ulong sid)
{
	struct tcp_vs_dest *dest = NULL;
	session_entry_t *session_entry, se;

	EnterFunction(6);

	se.sid = sid;
	spin_lock(&avl_tbl_lock);
	session_entry = avl_find(session_tbl, &se);
	spin_unlock(&avl_tbl_lock);

	if (session_entry != NULL) {
		dest = session_entry->dest;
	}

	LeaveFunction(6);
	return dest;
}


/****************************************************************************
*
*  Try to find a destination server for a  http request
*
*  1, for a http request with cookie header, find a destination server by
*     looking up the cookie table.
*
*  2, if cann't found a destination server in case 1, or for a http request
*     without cookie header, return the destination server with the least
*     load.
*
*/
static struct tcp_vs_dest *
tcp_vs_chttp_match(struct tcp_vs_service *svc, http_request_t * req)
{
	struct tcp_vs_dest *dest = NULL;

	EnterFunction(5);

	if (req->mime.session_id != 0) {
		dest = find_server_by_session_id(req->mime.session_id);
		TCP_VS_DBG(5,
			   "Find a destination server in session table\n");
	}

	if (dest == NULL) {
		dest = tcp_vs_chttp_matchrule(svc, req);
		/* FIXME: if session id is not 0 ??? */
	}

	LeaveFunction(5);
	return dest;
}

/****************************************************************************
*
*  This routine is called when the timer is expired.
*  It will delete the cookie from the cookie table and decrese the reference
*  count of the corresponding session table entry.  if the reference count
*  reach 0, then delete the session table entry from the session table.
*
*  Note: be care to call it directly. The system  will be deadlock if the spin
*	lock cookie_tbl_lock has been hold by the caller.
*/
static void
cookie_expire(unsigned long data)
{
	cookie_entry_t *cookie_entry = (cookie_entry_t *) data;
	session_entry_t *session_entry, se;
	ulong sid = cookie_entry->key->sid;

	EnterFunction(6);

	se.sid = sid;

	/* reduce the reference count in session table */
	spin_lock(&avl_tbl_lock);
	session_entry = avl_find(session_tbl, &se);
	if (session_entry != NULL) {
		session_entry->ref_cnt--;
		if (session_entry->ref_cnt == 0) {
			avl_delete(session_tbl, session_entry);
			kfree(session_entry);
		}
	} else {
		TCP_VS_ERR
		    ("ERROR: Can't find session id in session table.\n");
	}

	/* free the cookie table entry */
	avl_delete(cookie_tbl, cookie_entry);
	spin_unlock(&avl_tbl_lock);

	kfree(cookie_entry->key->name);
	kfree(cookie_entry->key);
	kfree(cookie_entry);

	LeaveFunction(6);
}


/****************************************************************************
*  New a cookie entry
*
*/
static cookie_entry_t *
new_cookie_entry(http_cookie_t * cookie)
{
	cookie_entry_t *ce;

	EnterFunction(6);

	assert(cookie != NULL);
	assert(cookie->max_age != 0);

	ce = (cookie_entry_t *) kmalloc(sizeof(cookie_entry_t), GFP_ATOMIC);
	if (ce != NULL) {
		ce->key = cookie->key;
		cookie->key = NULL;	/* avoid to be freed by free_cookie_list */
	}

	LeaveFunction(6);
	return ce;
}


/****************************************************************************
*  Update the cookie entry by cookie received.
*
*/
static void
update_cookie_entry(cookie_entry_t * cookie_entry, http_cookie_t * cookie)
{

	EnterFunction(6);

	if (cookie->discard == 1) {
		cookie->max_age =
		    MIN(COOKIE_DISCARD_TIME, cookie->max_age);
	}

	tcp_vs_del_slowtimer(&cookie_entry->cookie_expire_timer);
	cookie_entry->cookie_expire_timer.expires =
	    jiffies + cookie->max_age * HZ;
	tcp_vs_add_slowtimer(&cookie_entry->cookie_expire_timer);

	LeaveFunction(6);
	return;
}


/****************************************************************************
*    AVL TREE Walker to free the node <cookie_entry_t>
*/
static void
free_cookie_entry(void *avl_item, void *avl_param)
{
	cookie_entry_t *cookie_entry = (cookie_entry_t *) (avl_item);

	tcp_vs_del_slowtimer(&cookie_entry->cookie_expire_timer);
	kfree(cookie_entry->key->name);
	kfree(cookie_entry->key);
}


/****************************************************************************
*    AVL TREE Walker to free the node <session_entry_t>
*/
static void
free_session_entry(void *avl_item, void *avl_param)
{
	if (avl_item)
		kfree(avl_item);
}


/****************************************************************************
*    Free the memeory resource occupied by cookie table
*/
static void
free_avl_tables(void)
{
	if (cookie_tbl)
		avl_destroy(cookie_tbl, free_cookie_entry);
	if (session_tbl)
		avl_destroy(session_tbl, free_session_entry);
}


/****************************************************************************
*    Handle set-cookie2 header.
*    Add new session table entry or update existing session table entry.
*    Iterate the cookie list, add new cookie table entry into cookie table and
*  update existing cookie table entry.
*
*/
static int
http_set_cookie_handler(struct list_head *cookie_list,
			struct tcp_vs_dest *dest, ulong sid)
{
	struct list_head *l;
	cookie_entry_t *dup, *ce;
	session_entry_t *session_entry, *se;
	http_cookie_t *cookie = NULL;
	int ret = -1;

	EnterFunction(6);

	/* add the <session id, dest server>  to session table, or update the entry
	   reference count */
	session_entry =
	    (session_entry_t *) kmalloc(sizeof(session_entry_t),
					GFP_KERNEL);
	if (session_entry == NULL) {
		TCP_VS_ERR("Out of memory!\n");
		return -1;
	}

	session_entry->sid = sid;
	session_entry->dest = dest;
	session_entry->ref_cnt = 0;

	spin_lock(&avl_tbl_lock);

	se = avl_insert(session_tbl, session_entry);
	if (se != NULL) {	/* duplicate session entry */
		kfree(session_entry);
		session_entry = se;
	}

	/* add each cookie to cookie table or update its value */
	list_for_each(l, cookie_list) {
		cookie = list_entry(l, http_cookie_t, c_list);
		cookie->key->sid = sid;
		assert(cookie->key->name != NULL);

		ce = new_cookie_entry(cookie);
		if (ce == NULL) {
			TCP_VS_ERR("Out of memory!\n");
			goto out;
		}

		dup = avl_insert(cookie_tbl, ce);
		if (dup != NULL) {
			/* update cookie entry */
			update_cookie_entry(dup, cookie);
			kfree(ce);
		} else {	/* successfully inserted */
			session_entry->ref_cnt++;
			init_slowtimer(&ce->cookie_expire_timer);
			ce->cookie_expire_timer.data = (unsigned long) ce;
			ce->cookie_expire_timer.function = cookie_expire;
			ce->cookie_expire_timer.expires =
			    jiffies + cookie->max_age * HZ;
			tcp_vs_add_slowtimer(&ce->cookie_expire_timer);
		}
	}			/* end of list_for_each */

	ret = 0;
      out:
	free_cookie_list(cookie_list);
	spin_unlock(&avl_tbl_lock);
	LeaveFunction(6);
	return ret;
}


/****************************************************************************
*	get response from the specified server
*/
static int
chttp_get_response(struct socket *csock, server_conn_t * sc,
		   http_request_t * req, char *buffer,
		   int buflen, int *close)
{
	http_read_ctl_block_t read_ctl_blk;
	http_buf_t	buff;
	http_response_t resp;
	int len, ret = -1;
	struct socket *dsock = sc->sock;
	ulong sid = 0;


	EnterFunction(5);

	INIT_LIST_HEAD(&buff.b_list);
	buff.buf = buffer;
	buff.data_len = 0;

	memset(&read_ctl_blk, 0, sizeof(read_ctl_blk));
	INIT_LIST_HEAD(&read_ctl_blk.buf_entry_list);
	read_ctl_blk.cur_buf  = &buff;
	read_ctl_blk.buf_size = buflen;
	read_ctl_blk.sock = dsock;
	list_add (&buff.b_list, &read_ctl_blk.buf_entry_list);

	*close = 0;

	/* Do we have data ? */
	while (skb_queue_empty(&(dsock->sk->sk_receive_queue))) {
		interruptible_sleep_on_timeout(&dsock->wait, HZ);
	}

	/* read status line from server */
	len = http_read_line(&read_ctl_blk, 0);
	if (len < 0) {
		TCP_VS_ERR("Error in reading status line from server\n");
		goto exit;
	}

	/* xmit status line to client (2 more bytes for CRLF) */
	if (tcp_vs_xmit(csock, read_ctl_blk.info, len + 2, MSG_MORE) < 0) {
		TCP_VS_ERR("Error in sending status line\n");
		goto exit;
	}

	/* parse status line */
	memset(&resp, 0, sizeof(resp));
	if (parse_http_status_line(read_ctl_blk.info, len, &resp) ==
	    PARSE_ERROR) {
		goto exit;
	}

	/* parse MIME header */
	do {
		if ((len = http_read_line(&read_ctl_blk, 0)) < 0) {
			goto exit;
		}


		/*inject a cookie with session id at the end of the http header */
		if ((len == 0) && resp.mime.cookie) {
			sid = req->mime.session_id;
			if ((sid == 0) || (sid > ktcpvs_session_id)) {
				sid = inject_session_id_cookie(csock,
							       resp.mime.
							       set_cookie2);
			}
		}

		/* xmit MIME header (2 more bytes for CRLF) */
		if (tcp_vs_xmit
		    (csock, read_ctl_blk.info, len + 2, MSG_MORE) < 0) {
			TCP_VS_ERR("Error in sending status line\n");
			goto exit;
		}

		/* http_line_unescape (read_ctl_blk.info, len); */
		http_mime_parse(read_ctl_blk.info, len, &resp.mime);
	}
	while (len != 0);	/* http header end with CRLF,CRLF */

	*close = resp.mime.connection_close;

	if (resp.mime.cookie > 0) {
		ret =
		    http_set_cookie_handler(&resp.mime.cookie_list,
					    sc->dest, sid);
		if (ret != 0)
			goto exit;
	}

	/*
	 * Any response message which "MUST NOT" include a message-body (such
	 * as the 1xx, 204, and 304 responses and any response to a HEAD
	 * request) is always terminated by the first empty line after the
	 * header fields, regardless of the entity-header fields present in
	 * the message.
	 */
	if (req->method != HTTP_M_HEAD) {
		if ((resp.status_code < 200)
		    || (resp.status_code == 204
			|| resp.status_code == 304)) {
			ret = 0;
			goto exit;
		}

		ret =
		    relay_http_message_body(csock, &read_ctl_blk,
					    &resp.mime);
		if (resp.mime.sep) {
			kfree(resp.mime.sep);
		}
	}

      exit:
	LeaveFunction(5);
	return ret;
}


/****************************************************************************
*	Transmit http message header to destination socket
*
*/
static int
xmit_http_message_header(struct socket *dsock,
			 http_read_ctl_block_t * read_ctl)
{
	struct list_head *l, *temp;
	http_buf_t *buf_entry;
	int ret = 0;

	EnterFunction(5);

	TCP_VS_DBG(5, "HTTP Message Header:\n");

	list_for_each_safe(l, temp, &read_ctl->buf_entry_list) {
		buf_entry = list_entry(l, http_buf_t, b_list);

		if (tcp_vs_xmit(dsock, buf_entry->buf,
				buf_entry->data_len, MSG_MORE) < 0) {
			TCP_VS_ERR("Error in xmitting message header\n");
			ret = -1;
			break;
		}

		if (buf_entry != read_ctl->cur_buf) {
			list_del(l);
			free_page((unsigned long) buf_entry->buf);
			kfree(buf_entry);
		}
	}

	LeaveFunction(5);
	return ret;
}

/****************************************************************************
*
* http_read_reset - reset read buffer
*
*/
int
http_read_reset (http_read_ctl_block_t *ctl_blk)
{
	char* buf = ctl_blk->cur_buf->buf;

	memmove(buf, buf + ctl_blk->offset, ctl_blk->remaining);
	ctl_blk->offset = 0;
	return 0;
}

/****************************************************************************
*	HTTP content-based scheduling with cookie support:
*	Read and parse the whole http message header, and direct each http
*	message to the right server according to the scheduling rule.
*	returns:
*		0,	success, schedule just chose a dest server
*		1,	success, schedule has done all the jobs
*		-1,	redirect to the local server
*		-2,	error
*/
static int
tcp_vs_chttp_schedule(struct tcp_vs_conn *conn, struct tcp_vs_service *svc)
{
	http_request_t req;
	http_read_ctl_block_t read_ctl_blk;
	int ret = 1;		/* scheduler has done all the jobs */
	int len;
	unsigned long last_read;
	int close_server = 0;
	struct tcp_vs_dest *dest;
	struct socket *dsock;
	server_conn_t *sc;

	DECLARE_WAITQUEUE(wait, current);

	EnterFunction(5);

	conn->dest = NULL;
	conn->dsock = NULL;

	/* init buffer for http message header */
	if (http_read_init(&read_ctl_blk, conn->csock) != 0) {
		TCP_VS_ERR("Out of memory!\n");
		ret = -2;
		goto out;
	}

	/* Do we have data ? */
	while (skb_queue_empty(&(conn->csock->sk->sk_receive_queue))) {
		interruptible_sleep_on_timeout(&conn->csock->wait, HZ);
	}

	last_read = jiffies;
	do {
		switch (data_available(&read_ctl_blk)) {
		case -1:
			TCP_VS_DBG(5,
				   "Socket error before reading request line.\n");
			ret = -2;
			goto out;

		case 0:
			/* check if the service is stopped or system is
			   unloaded */
			if (svc->stop != 0 || sysctl_ktcpvs_unload != 0) {
				TCP_VS_DBG(5,
					   "cookie scheduling exit (pid=%d)\n",
					   current->pid);
				goto out;
			}

			if ((jiffies - last_read) >
			    sysctl_ktcpvs_keepalive_timeout * HZ) {
				TCP_VS_DBG(5, "Timeout, disconnect.\n");
				goto out;
			}

			add_wait_queue(read_ctl_blk.sock->sk->sk_sleep,
				       &wait);
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ);
			__set_current_state(TASK_RUNNING);
			remove_wait_queue(read_ctl_blk.sock->sk->sk_sleep,
					  &wait);
			continue;

		case 1:
			last_read = jiffies;
			break;
		}

		/* read request line from client socket */
		len = http_read_line(&read_ctl_blk, 1);
		if (len < 0) {
			TCP_VS_ERR
			    ("Error reading request line from client\n");
			ret = -2;
			goto out;
		}

		/* parse the http request line */
		memset(&req, 0, sizeof(req));
		if (parse_http_request_line(read_ctl_blk.info, len, &req)
		    != PARSE_OK) {
			TCP_VS_ERR("Cannot parse http request\n");
			ret = -2;
			goto out;
		}

		/* Process MIME header */
		do {
			len = http_read_line(&read_ctl_blk, 1);
			if (len < 0) {
				goto out;
			}
			http_mime_parse(read_ctl_blk.info, len, &req.mime);
		}
		while (len != 0);	/* http header end with CRLF,CRLF */


		/* select a server */
		dest = tcp_vs_chttp_match(svc, &req);
		if (!dest) {
			TCP_VS_DBG(5, "Can't find a right server\n");
			ret = -2;
			goto out;
		}

		/* lookup a server connection in the connection pool */
	      lookup_again:
		sc = tcp_vs_srvconn_get(dest->addr, dest->port);
		if (sc == NULL) {
			sc = tcp_vs_srvconn_new(dest);
			if (sc == NULL) {
				ret = -2;
				goto out;
			}
		}

		dsock = sc->sock;
		if (dsock->sk->sk_state != TCP_ESTABLISHED) {
			tcp_vs_srvconn_free(sc);
			goto lookup_again;
		}

		if (xmit_http_message_header(dsock, &read_ctl_blk) != 0) {
			goto out_free;
		}

		if (relay_http_message_body
		    (dsock, &read_ctl_blk, &req.mime) != 0) {
			TCP_VS_ERR("Error in sending http message body\n");
			goto out_free;
		}

		if (chttp_get_response(conn->csock, sc, &req, conn->buffer,
				       conn->buflen, &close_server) < 0) {
			goto out;
		}

		if (close_server) {
			TCP_VS_DBG(5, "Close server connection.\n");
			goto out_free;	/* close the connection? tbd */
		}

		/* have to put back the server connection when
		   it is not used */
		tcp_vs_srvconn_put(sc);

		http_read_reset(&read_ctl_blk);
	}
	while (req.mime.connection_close != 1);

      out:
	http_read_free(&read_ctl_blk);
	LeaveFunction(5);
	return ret;

      out_free:
	tcp_vs_srvconn_free(sc);
	goto out;
}

static struct tcp_vs_scheduler tcp_vs_chttp_scheduler = {
	{0},			/* n_list */
	"chttp",		/* name */
	THIS_MODULE,		/* this module */
	tcp_vs_chttp_init_svc,	/* initializer */
	tcp_vs_chttp_done_svc,	/* done */
	tcp_vs_chttp_update_svc,	/* update */
	tcp_vs_chttp_schedule,	/* select a server by http request */
};

static int __init
tcp_vs_chttp_init(void)
{
	int ret = -ENOMEM;

	cookie_tbl = avl_create(compare_cookie_entry, NULL, NULL);
	session_tbl = avl_create(compare_session_entry, NULL, NULL);

	if ((cookie_tbl != NULL) && (session_tbl != NULL)) {
		http_mime_parser_init();
		INIT_LIST_HEAD(&tcp_vs_chttp_scheduler.n_list);
		ret = register_tcp_vs_scheduler(&tcp_vs_chttp_scheduler);
	}

	return ret;
}

static void __exit
tcp_vs_chttp_cleanup(void)
{
	free_avl_tables();
	unregister_tcp_vs_scheduler(&tcp_vs_chttp_scheduler);
}

module_init(tcp_vs_chttp_init);
module_exit(tcp_vs_chttp_cleanup);
MODULE_LICENSE("GPL");
