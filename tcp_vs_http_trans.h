#ifndef _TCP_VS_HTTP_TRANS_H
#define _TCP_VS_HTTP_TRANS_H

/*
 * KTCPVS  -    Kernel TCP Virtual Server
 *
 * tcp_vs_http_trans.h: HTTP transport definition and function prototypes
 *
 * $Id: tcp_vs_http_trans.h,v 1.1 2003/06/14 16:09:47 wensong Exp $
 *
 * Authors:	Hai Long <david_lung@yahoo.com>
 *		Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 */


/* buffer to store http lines */
typedef struct http_buf_s {
	struct list_head	b_list;
	char			*buf;
	int			data_len;
} http_buf_t;

/*
 *	Control block to read data from socket
 */
typedef struct http_read_ctl_block_s {
	struct socket *sock;	/* socket that message read from */
	struct list_head buf_entry_list; /* buffer list */
	http_buf_t *cur_buf;	/* current buffer */
	char *info;		/* point to the current information */
	int offset;		/* offset of remaining bytes */
	int remaining;		/* remaining bytes not return */
	int buf_size;		/* buffer size */
	int flag;		/* read flag */
} http_read_ctl_block_t;


/* HTTP transport function prototypes */
extern int relay_http_message_body(struct socket *dsock,
				   http_read_ctl_block_t * ctl_blk,
				   http_mime_header_t * mime);

extern int http_read_init(http_read_ctl_block_t *ctl_blk, struct socket *sock);

extern void http_read_free(http_read_ctl_block_t *read_ctl);

extern int data_available(http_read_ctl_block_t * ctl_blk);

extern int http_read_line(http_read_ctl_block_t * ctl_blk, int grow);

#endif
