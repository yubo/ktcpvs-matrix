#ifndef _TCP_VS_HTTP_PARSER_H
#define _TCP_VS_HTTP_PARSER_H

/*
 * KTCPVS  -    Kernel TCP Virtual Server
 *
 * tcp_vs_http_parser.h: HTTP parser definition and function prototypes
 *
 * $Id: tcp_vs_http_parser.h,v 1.1 2003/06/14 16:09:47 wensong Exp $
 *
 * Authors:	Hai Long <david_lung@yahoo.com>
 *		Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 */


#define PARSE_OK		0
#define PARSE_INCOMPLETE	1
#define PARSE_ERROR		2

#define CR	13
#define LF	10
#define SP	' '


/**
 * @defgroup Methods List of Methods recognized by the server
 * @{
 */
#define HTTP_M_UNKNOWN		-1
#define HTTP_M_GET		0       /* RFC 2616: HTTP */
#define HTTP_M_HEAD		1
#define HTTP_M_PUT		2       /*  :             */
#define HTTP_M_POST		3
#define HTTP_M_DELETE		4
#define HTTP_M_CONNECT		5
#define HTTP_M_OPTIONS		6
#define HTTP_M_TRACE		7       /* RFC 2616: HTTP */
#define HTTP_M_PATCH		8       /* no rfc(!)  ### remove this one? */
#define HTTP_M_PROPFIND		9       /* RFC 2518: WebDAV */
#define HTTP_M_PROPPATCH	10	/*  :               */
#define HTTP_M_MKCOL		11
#define HTTP_M_COPY		12
#define HTTP_M_MOVE		13
#define HTTP_M_LOCK		14
#define HTTP_M_UNLOCK		15      /* RFC 2518: WebDAV */
#define HTTP_M_VERSION_CONTROL	16      /* RFC 3253: WebDAV Versioning */
#define HTTP_M_CHECKOUT		17      /*  :                          */
#define HTTP_M_UNCHECKOUT	18
#define HTTP_M_CHECKIN		19
#define HTTP_M_UPDATE		20
#define HTTP_M_LABEL		21
#define HTTP_M_REPORT		22
#define HTTP_M_MKWORKSPACE	23
#define HTTP_M_MKACTIVITY	24
#define HTTP_M_BASELINE_CONTROL	25
#define HTTP_M_MERGE		26
#define HTTP_M_INVALID		27      /* RFC 3253: WebDAV Versioning */

#define HTTP_VERSION(major,minor)	(1000*(major)+(minor))

/* cookie components that act as key */
typedef struct cookie_key_s {
	char *name;
	ulong sid;
} cookie_key_t;

/* HTTP cookie */
typedef struct http_cookie_s {
	struct list_head c_list;
	int discard;
	unsigned int max_age;
	cookie_key_t *key;
} http_cookie_t;

/* HTTP MIME header */
typedef struct http_mime_header_s {
	struct list_head cookie_list;
	int content_length;
	int transfer_encoding;
	int connection_close;
	char *sep;		/* THIS_STRING_SEPARATES */
	int cookie;		/* if there is cookie in the header */
	int set_cookie2;
	ulong session_id;
} http_mime_header_t;

typedef struct http_request_s {
	const char *message;
	unsigned int message_len;
	unsigned int parsed_len;

	/* request method */
	int method;
	const char *method_str;

	/* request URI */
	const char *uri_str;
	unsigned int uri_len;
	unsigned int method_len;

	/* http version */
	int version;
	const char *version_str;
	unsigned int version_len;

	/* MIME header */
	http_mime_header_t mime;
} http_request_t;

typedef struct http_response_s {
	/* http verison */
	int version;

	/* response status code */
	int status_code;

	/* MIME header */
	http_mime_header_t mime;
} http_response_t;


/* parser function prototypes */
extern int parse_http_request_line(char *buffer, size_t len,
				   http_request_t * req);

extern int parse_http_status_line(char *buffer, size_t len,
				  http_response_t * resp);

extern void http_mime_parser_init(void);

extern int http_mime_parse(char *buffer, int len,
			   http_mime_header_t * mime);

extern char* search_sep(const char *s, int len, const char *sep);

extern long get_chunk_size(char *b);


#endif		/* _TCP_VS_HTTP_PARSER_H */
