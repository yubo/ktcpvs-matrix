/*
 * KTCPVS       An implementation of the TCP Virtual Server daemon inside
 *              kernel for the LINUX operating system. KTCPVS can be used
 *              to build a moderately scalable and highly available server
 *              based on a cluster of servers, with more flexibility.
 *
 * tcp_vs_http_parser.c: KTCPVS HTTP parsing engine
 *
 * Version:     $Id: tcp_vs_http_parser.c,v 1.4 2003/06/14 16:09:47 wensong Exp $
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

#include <linux/sched.h>
#include <linux/ctype.h>

#include "tcp_vs.h"
#include "tcp_vs_http_parser.h"

#define HTTP_VERSION_HEADER_LEN		5
#define HTTP_VERSION_NUMBER_LEN		3

const char *http_version_header = "HTTP/";

#define DEFAULT_MAX_COOKIE_AGE	1800
#define MAX_MIME_HEADER_STRING_LEN	64

typedef void (*HTTP_MIME_PARSER) (http_mime_header_t * mime, char *buffer);

typedef struct http_mime_parse_s {
	struct list_head plist;
	HTTP_MIME_PARSER parser;
	char mime_header_string[MAX_MIME_HEADER_STRING_LEN];
} http_mime_parse_t;

static http_mime_parse_t http_mime_parse_table[MAX_MIME_HEADER_STRING_LEN];


/****************************************************************************
*	skip whitespace
*       LWS            = [CRLF] 1*( SP | HT )
*/
static inline char *
skip_lws(const char *buffer)
{
	char *s = (char *) buffer;
	while ((*s == ' ') || (*s == '\t')) {
		s++;
	}
	return s;
}


/****************************************************************************
*	search the seperator in a string
*/
char *
search_sep(const char *s, int len, const char *sep)
{
	int l, ll;

	l = strlen(sep);
	if (!l)
		return (char *) s;

	ll = len;
	while (ll >= l) {
		ll--;
		if (!memcmp(s, sep, l))
			return (char *) s;
		s++;
	}
	return NULL;
}


/****************************************************************************
*	extract the attribute-value pair
*	The input string has the form: A = "V", and it will also accept
*	A = V too.
*	return:
*		0  -- OK, and parse end.
*		\; -- OK, end with a ';'
*		\, -- OK, end with a ','
*		1  -- parse error.
*	Note:
*	The input buffer will be modified by this routine. be care!
*
*/
static int
extract_av(char **buffer, char **attribute, char **value)
{
	char *begin, *end, *pos, *a, *v;
	char c;
	int ret = 1;
	int flag = 0;

	a = v = end = NULL;

	/* get attribute */
	pos = a = begin = skip_lws(*buffer);
	for (;;) {
		c = *pos;
		switch (c) {
		case ' ':
		case '\t':
			end = pos;
			*end = 0;
			break;
		case '=':
			if (end == NULL) {
				end = pos;
				*end = 0;
			}
			goto get_value;
		case ';':
		case ',':
		case 0:
			if (end == NULL) {
				end = pos;
				*end = 0;
			}
			ret = c;
			goto exit;
		}
		pos++;
	}

      get_value:
	pos++;
	/* get value */
	pos = v = begin = skip_lws(pos);
	end = NULL;
	if (*pos == '"') {
		flag = 1;
		pos++;
		v++;
	}

	for (;;) {
		c = *pos;
		switch (c) {
		case ' ':
		case '\t':
			if ((flag == 0) && (end == NULL)) {
				end = pos;
				*end = 0;
			}
			break;
		case '"':
			if (flag == 1) {
				end = pos;
				*end = 0;
				flag = 0;
			}
			break;
		case ';':
		case ',':
			if (flag == 0) {
				if (end == NULL) {
					end = pos;
					*end = 0;
				}
				ret = c;
				goto exit;
			}
			break;
		case 0:
			if (end == NULL) {
				end = pos;
				*end = 0;
			}
			ret = c;
			goto exit;
		}
		pos++;
	}


      exit:
	if (*a == 0) {
		a = NULL;
	}

	if ((v != NULL) && (*v == 0)) {
		v = NULL;
	}

	if (ret > 1) {
		*buffer = (pos + 1);
	}
	*attribute = a;
	*value = v;
	return ret;
}


/****************************************************************************
*	This doesn't accept 0x if the radix is 16. The overflow code assumes
*	a 2's complement architecture
*/
#ifndef strtol
static long
strtol(char *string, char **endptr, int radix)
{
	char *s;
	long value;
	long new_value;
	int sign;
	int increment;

	value = 0;
	sign = 1;
	s = string;

	if ((radix == 1) || (radix > 36) || (radix < 0)) {
		goto done;
	}

	/* skip whitespace */
	while ((*s == ' ') || (*s == '\t') || (*s == '\n') || (*s == '\r')) {
		s++;
	}

	if (*s == '-') {
		sign = -1;
		s++;
	} else if (*s == '+') {
		s++;
	}

	if (radix == 0) {
		if (*s == '0') {
			s++;
			if ((*s == 'x') || (*s == 'X')) {
				s++;
				radix = 16;
			} else
				radix = 8;
		} else
			radix = 10;
	}

	/* read number */
	while (1) {
		if ((*s >= '0') && (*s <= '9'))
			increment = *s - '0';
		else if ((*s >= 'a') && (*s <= 'z'))
			increment = *s - 'a' + 10;
		else if ((*s >= 'A') && (*s <= 'Z'))
			increment = *s - 'A' + 10;
		else
			break;

		if (increment >= radix)
			break;

		new_value = value * radix + increment;
		/* detect overflow */
		if ((new_value - increment) / radix != value) {
			s = string;
			value = -1 >> 1;
			if (sign < 0)
				value += 1;

			goto done;
		}

		value = new_value;
		s++;
	}

      done:
	if (endptr)
		*endptr = s;

	return value * sign;
}
#endif


/****************************************************************************
*  Parse a chunk extension, detect overflow.
*  There are two error cases:
*  1) If the conversion would require too many bits, a -1 is returned.
*  2) If the conversion used the correct number of bits, but an overflow
*     caused only the sign bit to flip, then that negative number is
*     returned.
*  In general, any negative number can be considered an overflow error.
*/
long
get_chunk_size(char *b)
{
	long chunksize = 0;
	size_t chunkbits = sizeof(long) * 8;

	/* skip whitespace */
	while ((*b == ' ') || (*b == '\t') || (*b == '\n') || (*b == '\r')) {
		b++;
	}

	/* Skip leading zeros */
	while (*b == '0') {
		++b;
	}

	while (isxdigit(*b) && (chunkbits > 0)) {
		int xvalue = 0;

		if (*b >= '0' && *b <= '9') {
			xvalue = *b - '0';
		} else if (*b >= 'A' && *b <= 'F') {
			xvalue = *b - 'A' + 0xa;
		} else if (*b >= 'a' && *b <= 'f') {
			xvalue = *b - 'a' + 0xa;
		}

		chunksize = (chunksize << 4) | xvalue;
		chunkbits -= 4;
		++b;
	}
	if (isxdigit(*b) && (chunkbits <= 0)) {
		/* overflow */
		return -1;
	}

	return chunksize;
}

/****************************************************************************
 *
 *  This routine is borrowed from apache server
 */
static int
lookup_builtin_method(const char *method, int len)
{
	/* Note: the following code was generated by the "shilka" tool from
	   the "cocom" parsing/compilation toolkit. It is an optimized lookup
	   based on analysis of the input keywords. Postprocessing was done
	   on the shilka output, but the basic structure and analysis is
	   from there. Should new HTTP methods be added, then manual insertion
	   into this code is fine, or simply re-running the shilka tool on
	   the appropriate input. */

	switch (len) {
	case 3:
		switch (method[0]) {
		case 'P':
			return (method[1] == 'U'
				&& method[2] == 'T'
				? HTTP_M_PUT : HTTP_M_UNKNOWN);
		case 'G':
			return (method[1] == 'E'
				&& method[2] == 'T'
				? HTTP_M_GET : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 4:
		switch (method[0]) {
		case 'H':
			return (method[1] == 'E'
				&& method[2] == 'A'
				&& method[3] == 'D'
				? HTTP_M_GET : HTTP_M_UNKNOWN);
		case 'P':
			return (method[1] == 'O'
				&& method[2] == 'S'
				&& method[3] == 'T'
				? HTTP_M_POST : HTTP_M_UNKNOWN);
		case 'M':
			return (method[1] == 'O'
				&& method[2] == 'V'
				&& method[3] == 'E'
				? HTTP_M_MOVE : HTTP_M_UNKNOWN);
		case 'L':
			return (method[1] == 'O'
				&& method[2] == 'C'
				&& method[3] == 'K'
				? HTTP_M_LOCK : HTTP_M_UNKNOWN);
		case 'C':
			return (method[1] == 'O'
				&& method[2] == 'P'
				&& method[3] == 'Y'
				? HTTP_M_COPY : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 5:
		switch (method[2]) {
		case 'T':
			return (memcmp(method, "PATCH", 5) == 0
				? HTTP_M_PATCH : HTTP_M_UNKNOWN);
		case 'R':
			return (memcmp(method, "MERGE", 5) == 0
				? HTTP_M_MERGE : HTTP_M_UNKNOWN);
		case 'C':
			return (memcmp(method, "MKCOL", 5) == 0
				? HTTP_M_MKCOL : HTTP_M_UNKNOWN);
		case 'B':
			return (memcmp(method, "LABEL", 5) == 0
				? HTTP_M_LABEL : HTTP_M_UNKNOWN);
		case 'A':
			return (memcmp(method, "TRACE", 5) == 0
				? HTTP_M_TRACE : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 6:
		switch (method[0]) {
		case 'U':
			switch (method[5]) {
			case 'K':
				return (memcmp(method, "UNLOCK", 6) == 0
					? HTTP_M_UNLOCK : HTTP_M_UNKNOWN);
			case 'E':
				return (memcmp(method, "UPDATE", 6) == 0
					? HTTP_M_UPDATE : HTTP_M_UNKNOWN);
			default:
				return HTTP_M_UNKNOWN;
			}
		case 'R':
			return (memcmp(method, "REPORT", 6) == 0
				? HTTP_M_REPORT : HTTP_M_UNKNOWN);
		case 'D':
			return (memcmp(method, "DELETE", 6) == 0
				? HTTP_M_DELETE : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 7:
		switch (method[1]) {
		case 'P':
			return (memcmp(method, "OPTIONS", 7) == 0
				? HTTP_M_OPTIONS : HTTP_M_UNKNOWN);
		case 'O':
			return (memcmp(method, "CONNECT", 7) == 0
				? HTTP_M_CONNECT : HTTP_M_UNKNOWN);
		case 'H':
			return (memcmp(method, "CHECKIN", 7) == 0
				? HTTP_M_CHECKIN : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 8:
		switch (method[0]) {
		case 'P':
			return (memcmp(method, "PROPFIND", 8) == 0
				? HTTP_M_PROPFIND : HTTP_M_UNKNOWN);
		case 'C':
			return (memcmp(method, "CHECKOUT", 8) == 0
				? HTTP_M_CHECKOUT : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 9:
		return (memcmp(method, "PROPPATCH", 9) == 0
			? HTTP_M_PROPPATCH : HTTP_M_UNKNOWN);

	case 10:
		switch (method[0]) {
		case 'U':
			return (memcmp(method, "UNCHECKOUT", 10) == 0
				? HTTP_M_UNCHECKOUT : HTTP_M_UNKNOWN);
		case 'M':
			return (memcmp(method, "MKACTIVITY", 10) == 0
				? HTTP_M_MKACTIVITY : HTTP_M_UNKNOWN);
		default:
			return HTTP_M_UNKNOWN;
		}

	case 11:
		return (memcmp(method, "MKWORKSPACE", 11) == 0
			? HTTP_M_MKWORKSPACE : HTTP_M_UNKNOWN);

	case 15:
		return (memcmp(method, "VERSION-CONTROL", 15) == 0
			? HTTP_M_VERSION_CONTROL : HTTP_M_UNKNOWN);

	case 16:
		return (memcmp(method, "BASELINE-CONTROL", 16) == 0
			? HTTP_M_BASELINE_CONTROL : HTTP_M_UNKNOWN);

	default:
		return HTTP_M_UNKNOWN;
	}

	/* NOTREACHED */
}


/****************************************************************************
*   Parse http request line. (request line is terminated by CRLF)
*
*   RFC 2616, 19.3
*   Clients SHOULD be tolerant in parsing the Status-Line and servers
*   tolerant when parsing the Request-Line. In particular, they SHOULD
*   accept any amount of SP or HT characters between fields, even though
*   only a single SP is required.
*
*/
int
parse_http_request_line(char *buffer, size_t size, http_request_t * req)
{
	char *pos, *method, *ver;
	char c;
	int ret = PARSE_ERROR;
	int len, major, minor;

	EnterFunction(5);

	/* terminate string */
	c = buffer[size];
	buffer[size] = 0;

	TCP_VS_DBG(5, "parsing request:\n");
	TCP_VS_DBG(5, "--------------------\n");
	TCP_VS_DBG(5, "%s\n", buffer);
	TCP_VS_DBG(5, "--------------------\n");

	req->message = buffer;
	req->message_len = size;

	/*
	 * RFC 2616, 5.1:
	 *      Request-Line = Method SP Request-URI SP HTTP-Version CRLF
	 */

	/* try to get method */
	method = skip_lws(buffer);
	if ((pos = strchr((char *) method, SP)) == NULL) {
		goto exit;
	}
	len = pos - method;

	req->method = lookup_builtin_method(method, len);
	if (req->method == HTTP_M_UNKNOWN) {
		TCP_VS_ERR("Unknow http method.\n");
		goto exit;
	}

	/* get URI string */
	req->uri_str = skip_lws(pos + 1);
	if ((pos = strchr((char *) req->uri_str, SP)) == NULL) {
		goto exit;
	}
	req->uri_len = pos - req->uri_str;

	/* get http version */
	req->version_str = skip_lws(pos + 1);

	if (strnicmp(req->version_str,
		     http_version_header, HTTP_VERSION_HEADER_LEN) != 0) {
		goto exit;
	}

	ver = (char *) req->version_str + HTTP_VERSION_HEADER_LEN;
	len = strlen(ver);

	/* Avoid sscanf in the common case */
	if (len == HTTP_VERSION_NUMBER_LEN
	    && isdigit(ver[0]) && ver[1] == '.' && isdigit(ver[2])) {
		req->version = HTTP_VERSION(ver[0] - '0', ver[2] - '0');
	} else if (2 == sscanf(ver, "%u.%u", &major, &minor)
		   && (minor < HTTP_VERSION(1, 0)))	/* don't allow HTTP/0.1000 */
		req->version = HTTP_VERSION(major, minor);
	else
		req->version = HTTP_VERSION(1, 0);

	ret = PARSE_OK;
      exit:
	buffer[size] = c;	/* restore string */
	LeaveFunction(5);
	return ret;
}


/****************************************************************************
* parse_http_status_line - parse the http status line.
*
*   RFC 2616, 19.3
*   Clients SHOULD be tolerant in parsing the Status-Line and servers
*   tolerant when parsing the Request-Line. In particular, they SHOULD
*   accept any amount of SP or HT characters between fields, even though
*   only a single SP is required.
*
*/
int
parse_http_status_line(char *buffer, size_t size, http_response_t * resp)
{
	char *pos, *ver;
	char c;
	int len, major, minor;

	EnterFunction(5);

	assert(buffer != NULL);

	/* terminate string */
	c = buffer[size];
	buffer[size] = '\0';

	TCP_VS_DBG(5, "parsing response:\n");
	TCP_VS_DBG(5, "--------------------\n");
	TCP_VS_DBG(5, "%s\n", buffer);
	TCP_VS_DBG(5, "--------------------\n");

	/*
	 * RFC 2616, 6.1:
	 *      Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
	 */

	ver = skip_lws(buffer);
	if ((pos = strchr((char *) ver, SP)) == NULL) {
		return PARSE_ERROR;
	}

	if (strnicmp(ver,
		     http_version_header, HTTP_VERSION_HEADER_LEN) != 0) {
		return PARSE_ERROR;
	}

	ver += HTTP_VERSION_HEADER_LEN;
	len = pos - ver;

	/* Avoid sscanf in the common case */
	if (len == HTTP_VERSION_NUMBER_LEN
	    && isdigit(ver[0]) && ver[1] == '.' && isdigit(ver[2])) {
		resp->version = HTTP_VERSION(ver[0] - '0', ver[2] - '0');
	} else if (2 == sscanf(ver, "%u.%u", &major, &minor)
		   && (minor < HTTP_VERSION(1, 0)))	/* don't allow HTTP/0.1000 */
		resp->version = HTTP_VERSION(major, minor);
	else
		resp->version = HTTP_VERSION(1, 0);


	/* get the status code */
	resp->status_code = strtol(pos + 1, NULL, 10);
	assert(resp->status_code >= 100);
	TCP_VS_DBG(6, "Status Code: %d\n", resp->status_code);

	buffer[size] = c;	/* restore string */
	LeaveFunction(5);

	return PARSE_OK;
}


/****************************************************************************
* http_line_unescape - convert escaped characters in buffer to ASCII
*
* This routine can be used to convert an "escaped" form of a URL or
* parameter (appended to a URL) to standard ASCII format.
* The escaping is done by the browser on the client side, for
* transferring characters not allowed by the HTTP protocol.
* For example, a whitespace character is not allowed in an URL.
* It must be substituted by an escape sequence to be transferred.
*
* ESCAPING
* When you want to include any character, not part of the standard
* set allowed in URLs, you can do this by specifying its hex value
* in the format %xx, where xx is the hex representation.
* In addition, every '+' character will be substituted by a space.
*
*/
#if 0
static void
http_line_unescape(char *string,	/* escaped string to unescape */
		   int len	/* length of the string */
    )
{
	int i = 0;
	char buffer[3];
	char c;

	EnterFunction(5);

	assert(string != NULL);

	while (i < len) {
		if (string[i] == '+') {
			string[i] = ' ';	/* replace '+' by spaces */
		}
		if ((string[i] == '%') && (i < len - 2)) {
			if (isxdigit(string[i + 1])
			    && isxdigit(string[i + 2])) {
				strncpy(buffer, &(string[i + 1]), 2);
				buffer[2] = 0;
				c = (char) strtol(buffer, NULL, 16);
				if (c != 0) {
					memmove(&(string[i]),	/* move string 2 chars */
						&(string[i + 2]), 2);
					string[i] = c;	/* replace % by new char */
					len -= 2;
				}
			}
		}
		i++;
	}

	LeaveFunction(5);
	return;
}
#endif

/****************************************************************************
*
* register_mime_parser - register a http mime header parser
*
*/
static void
register_mime_parser(HTTP_MIME_PARSER parser, char *mime_str)
{
	int index;
	http_mime_parse_t *parse_entry, *new_entry;

	assert(parser != NULL);
	assert(mime_str != NULL);

	index = strlen(mime_str);
	if (index >= MAX_MIME_HEADER_STRING_LEN)
		return;

	parse_entry = &http_mime_parse_table[index];
	if (parse_entry->parser == NULL) {
		INIT_LIST_HEAD(&parse_entry->plist);
	} else {
		if (strnicmp
		    (mime_str, parse_entry->mime_header_string,
		     index) == 0) {
			return;
		}
		new_entry = kmalloc(sizeof(http_mime_parse_t), GFP_KERNEL);
		if (new_entry == NULL) {
			TCP_VS_ERR("Out of memory!\n");
			return;
		}
		list_add_tail(&new_entry->plist, &parse_entry->plist);
		parse_entry = new_entry;
	}

	strcpy(parse_entry->mime_header_string, mime_str);
	parse_entry->parser = parser;
}

/****************************************************************************
*
* transfer_encoding_parser - http mime header parser for "Transfer-Encoding"
*
*/
static void
transfer_encoding_parser(http_mime_header_t * mime, char *buffer)
{
	EnterFunction(6);

	if (strnicmp(buffer, "chunked", 7) == 0) {
		mime->transfer_encoding = 1;
		TCP_VS_DBG(6, "Transfer-Encoding: chunked\n");
	}

	LeaveFunction(6);
	return;
}


/****************************************************************************
*
* content_length_parser - http mime header parser for "Content-Length"
*
*/
static void
content_length_parser(http_mime_header_t * mime, char *buffer)
{
	EnterFunction(6);

	mime->content_length = strtol(buffer, NULL, 10);
	TCP_VS_DBG(6, "Content-Length: %d\n", mime->content_length);

	LeaveFunction(6);
	return;
}


/****************************************************************************
*
* connection_parser - http mime header parser for "Connection"
*
*/
static void
connection_parser(http_mime_header_t * mime, char *buffer)
{
	EnterFunction(6);

	if (strnicmp(buffer, "close", 5) == 0) {
		mime->connection_close = 1;
		TCP_VS_DBG(5, "Connection: close\n");
	}

	LeaveFunction(6);
	return;
}

/****************************************************************************
*
* content_type_parser - http mime header parser for "Content-type"
*
* Note: buffer should be a NULL terminated string.
*/
static void
content_type_parser(http_mime_header_t * mime, char *buffer)
{
	int sep_len;
	char *pos;

	EnterFunction(6);

	if (strnicmp(buffer, "multipart/byteranges", 20) == 0) {
		TCP_VS_DBG(6, "multipart/byteranges\n");
		pos = buffer + 20 + 1;	/* skip ';' */
		pos = skip_lws(pos + 1);
		if (strnicmp(pos, "boundary=", 9) != 0) {
			goto exit;
		}

		/* the rest of this line is THIS_STRING_SEPARATES */
		pos += 9;
		sep_len = strlen(pos);
		if ((mime->sep = kmalloc(sep_len + 1, GFP_KERNEL)) == NULL) {
			goto exit;
		}

		/* RFC 2046 [40] permits the boundary string to be quoted */
		if (pos[0] == '"' || pos[0] == '\'') {
			pos++;
			sep_len--;
		}
		strncpy(mime->sep, pos, sep_len);
		mime->sep[sep_len] = 0;
		TCP_VS_DBG(5, "THIS_STRING_SEPARATES : %s\n", mime->sep);
	}

      exit:
	LeaveFunction(6);
	return;
}


/****************************************************************************
*
* set_cookie_parser - http mime header parser for "Set-Cookie"
*
*   set-cookie      =       "Set-Cookie:" cookies
*   cookies         =       1#cookie
*   cookie          =       NAME "=" VALUE *(";" cookie-av)
*   NAME            =       attr
*   VALUE           =       value
*   cookie-av       =       "Comment" "=" value
*                   |       "Domain" "=" value
*                   |       "Max-Age" "=" value
*                   |       "Path" "=" value
*                   |       "Secure"
*                   |       "Version" "=" 1*DIGIT*
*
*/
static void
set_cookie_parser(http_mime_header_t * mime, char *buf)
{
	http_cookie_t *ck;
	char* buffer;
	char *attribute, *value, *s;
	int r;

	EnterFunction(6);

	buffer = strdup(buf);
	TCP_VS_DBG(5, "Set-Cookie:%s", buffer);

	mime->set_cookie2 = 0;

	if (mime->cookie == 0) {
		INIT_LIST_HEAD(&mime->cookie_list);
	}

	s = skip_lws(buffer);
	for (;;) {
	      parse_again:
		r = extract_av(&s, &attribute, &value);
		if (r == 1) {
			TCP_VS_ERR("Error while get Name & Value\n");
			goto out;
		}

		ck =
		    (http_cookie_t *) kmalloc(sizeof(http_cookie_t),
					      GFP_KERNEL);
		if (ck == NULL) {
			goto out;
		}
		memset(ck, 0, sizeof(http_cookie_t));

		ck->key =
		    (cookie_key_t *) kmalloc(sizeof(cookie_key_t),
					     GFP_KERNEL);
		if (ck->key == NULL) {
			kfree(ck);
			goto out;
		}
		memset(ck->key, 0, sizeof(cookie_key_t));
		ck->max_age = DEFAULT_MAX_COOKIE_AGE;

		mime->cookie++;
		list_add_tail(&ck->c_list, &mime->cookie_list);

		ck->key->name = strdup(attribute);
		if (r == 0) {
			goto out;
		}

		while (1) {
			r = extract_av(&s, &attribute, &value);
			if (r == 1) {
				TCP_VS_ERR("Error while get other AV\n");
				goto out;
			}

			if (strcmp(attribute, "Max-Age") == 0) {
				ck->max_age = strtol(value, NULL, 10);
			}

			switch (r) {
			case 0:
			case 1:
				goto out;
				break;
			case ';':
				continue;
			case ',':
				goto parse_again;
			}
		}		/* end while (1) */

	}			/* end for */

      out:
	kfree(buffer);
	LeaveFunction(6);
	return;
}

/****************************************************************************
*
* set_cookie2_parser - http mime header parser for "Set-Cookie2"
*
*   set-cookie      =       "Set-Cookie2:" cookies
*   cookies         =       1#cookie
*   cookie          =       NAME "=" VALUE *(";" set-cookie-av)
*   NAME            =       attr
*   VALUE           =       value
*   set-cookie-av   =       "Comment" "=" value
*                   |       "CommentURL" "=" <"> http_URL <">
*                   |       "Discard"
*                   |       "Domain" "=" value
*                   |       "Max-Age" "=" value
*                   |       "Path" "=" value
*                   |       "Port" [ "=" <"> portlist <"> ]
*                   |       "Secure"
*                   |       "Version" "=" 1*DIGIT
*   portlist        =       1#portnum
*   portnum         =       1*DIGIT
*
*/
static void
set_cookie2_parser(http_mime_header_t * mime, char *buf)
{
	http_cookie_t *ck;
	char *attribute, *value, *s;
	char *buffer;
	int r;

	EnterFunction(6);

	buffer = strdup(buf);
	TCP_VS_DBG(5, "Set-Cookie2:%s", buffer);

	mime->set_cookie2 = 1;

	if (mime->cookie == 0) {
		INIT_LIST_HEAD(&mime->cookie_list);
	}

	s = skip_lws(buffer);
	for (;;) {
	      parse_again:
		r = extract_av(&s, &attribute, &value);
		if (r == 1) {
			TCP_VS_ERR("Error while extract NAME & VALUE\n");
			goto out;
		}

		ck =
		    (http_cookie_t *) kmalloc(sizeof(http_cookie_t),
					      GFP_KERNEL);
		if (ck == NULL) {
			goto out;
		}
		memset(ck, 0, sizeof(http_cookie_t));

		ck->key =
		    (cookie_key_t *) kmalloc(sizeof(cookie_key_t),
					     GFP_KERNEL);
		if (ck->key == NULL) {
			kfree(ck);
			goto out;
		}
		memset(ck->key, 0, sizeof(cookie_key_t));
		ck->max_age = DEFAULT_MAX_COOKIE_AGE;

		mime->cookie++;
		list_add_tail(&ck->c_list, &mime->cookie_list);

		ck->key->name = strdup(attribute);
		if (r == 0) {
			goto out;
		}

		while (1) {
			r = extract_av(&s, &attribute, &value);
			if (r == 1) {
				TCP_VS_ERR
				    ("Error while extract other AV.\n");
				goto out;
			}

			if (strcmp(attribute, "Max-Age") == 0) {
				ck->max_age = strtol(value, NULL, 10);
			} else if (strcmp(attribute, "Discard") == 0) {
				ck->discard = 1;
			}
			switch (r) {
			case 0:
			case 1:
				goto out;
				break;
			case ';':
				continue;
			case ',':
				goto parse_again;
			}
		}		/* end while (1) */

	}			/* end for */

      out:
	kfree(buffer);
	LeaveFunction(6);
	return;
}

/****************************************************************************
*
* cookie_parser - http mime header parser for "Cookie"
*
*	cookie          =  "Cookie:" cookie-version 1*((";" | ",") cookie-value)
*	cookie-value    =  NAME "=" VALUE [";" path] [";" domain] [";" port]
*	cookie-version  =  "$Version" "=" value
*	NAME            =  attr
*	VALUE           =  value
*	path            =  "$Path" "=" value
*	domain          =  "$Domain" "=" value
*	port            =  "$Port" [ "=" <"> value <"> ]
*
*	Note: We only have interest in the KTCPVS_SID cookie, other cookie will be
*	      omitted.
*/
static void
cookie_parser(http_mime_header_t * mime, char *buf)
{
	char *pos, *attribute, *value;
	char* buffer;
	int r = 2;

	EnterFunction(6);

	buffer = strdup(buf);
	TCP_VS_DBG(5, "\nCookie:%s ", buffer);

	pos = skip_lws(buffer);
	while (r > 1) {
		r = extract_av(&pos, &attribute, &value);
		if (r == 1) {
			TCP_VS_ERR("Error while parse cookie header.\n");
			break;
		}

		if (strcmp(attribute, "KTCPVS_SID") == 0) {
			mime->session_id = strtol(value, NULL, 10);
			break;
		}
	}

	kfree(buffer);
	LeaveFunction(6);
	return;
}

void
http_mime_parser_init(void)
{
	memset(http_mime_parse_table, 0, sizeof(http_mime_parse_table));
	register_mime_parser(transfer_encoding_parser, "Transfer-Encoding");
	register_mime_parser(content_length_parser, "Content-Length");
	register_mime_parser(connection_parser, "Connection");
	register_mime_parser(content_type_parser, "Content-type");
	register_mime_parser(set_cookie_parser, "Set-Cookie");
	register_mime_parser(set_cookie2_parser, "Set-Cookie2");
	register_mime_parser(cookie_parser, "Cookie");
}

/******************************************************************************
* http_mime_parse - parse MIME line in a buffer
*
* This routine parses the MIME line in a buffer.
*
* NOTE: Some MIME headers (host, Referer) need be considered again, tbd.
*
*/
int
http_mime_parse(char *buffer, int len, http_mime_header_t * mime)
{
	char *pos, c;
	int l, ret = PARSE_OK;
	http_mime_parse_t *parse_entry, *pe;

	assert(buffer != NULL);

	/* terminate string */
	c = buffer[len];
	buffer[len] = 0;

	TCP_VS_DBG(5, "MIME Header: %s\n", buffer);

	buffer = skip_lws(buffer);
	if ((pos = strchr(buffer, ':')) == NULL) {
		ret = PARSE_ERROR;
		goto exit;
	}

	l = pos - buffer;
	if (l >= MAX_MIME_HEADER_STRING_LEN)
		goto exit;

	parse_entry = &http_mime_parse_table[l];

	if (parse_entry->parser == NULL) {	/* an unregistered mime header */
		goto exit;
	}

	assert(parse_entry->mime_header_string != NULL);

	if (strnicmp(parse_entry->mime_header_string, buffer, l) != 0) {
		struct list_head *list;
		int found = 0;
		list_for_each(list, &parse_entry->plist) {
			pe = list_entry(list, http_mime_parse_t, plist);
			if (strnicmp(pe->mime_header_string, buffer, l) ==
			    0) {
				parse_entry = pe;
				found = 1;
				break;
			}
		}
		if (!found)	/* an unregistered mime header */
			goto exit;
	}

	pos = skip_lws(pos + 1);
	parse_entry->parser(mime, pos);

      exit:
	buffer[len] = c;	/* restore string */
	return ret;
}
