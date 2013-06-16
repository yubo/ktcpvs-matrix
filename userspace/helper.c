/*
 * helper.c:	various conversion and parsing helpers
 *
 * Version:	$Id: helper.c,v 1.2 2003/05/23 02:08:34 wensong Exp $
 *
 * Authors:	Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "helper.h"

int
string_to_number(const char *s, int min, int max)
{
	long number;
	char *end;

	errno = 0;
	number = strtol(s, &end, 10);
	if (*end == '\0' && end != s) {
		/* We parsed a number, let's see if we want this. */
		if (errno != ERANGE && min <= number && number <= max)
			return number;
	}
	return -1;
}

int
host_to_addr(const char *name, struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyname(name)) != NULL) {
		if (host->h_addrtype != AF_INET ||
		    host->h_length != sizeof(struct in_addr)) return -1;
		/* warning: we just handle h_addr_list[0] here */
		memcpy(addr, host->h_addr_list[0], sizeof(struct in_addr));
		return 0;
	}
	return -1;
}


char *
addr_to_host(struct in_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyaddr((char *) addr,
				  sizeof(struct in_addr),
				  AF_INET)) !=
	    NULL) return (char *) host->h_name;
	else
		return (char *) NULL;
}


char *
addr_to_anyname(struct in_addr *addr)
{
	char *name;

	if ((name = addr_to_host(addr)) != NULL)
		return name;
	else
		return inet_ntoa(*addr);
}


int
service_to_port(const char *name, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP
	    && (service = getservbyname(name, "tcp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else if (proto == IPPROTO_UDP
		 && (service = getservbyname(name, "udp")) != NULL)
		return ntohs((unsigned short) service->s_port);
	else
		return -1;
}


char *
port_to_service(unsigned int port, unsigned short proto)
{
	struct servent *service;

	if (proto == IPPROTO_TCP &&
	    (service = getservbyport(htons(port), "tcp")) != NULL)
		return service->s_name;
	else if (proto == IPPROTO_UDP &&
		 (service = getservbyport(htons(port), "udp")) != NULL)
		return service->s_name;
	else
		return (char *) NULL;
}


char *
port_to_anyname(unsigned int port, unsigned short proto)
{
	char *name;
	static char buf[10];

	if ((name = port_to_service(port, proto)) != NULL)
		return name;
	else {
		sprintf(buf, "%u", port);
		return buf;
	}
}


char *
addrport_to_anyname(struct in_addr *addr, unsigned int port,
		    unsigned short proto, unsigned int format)
{
	char *buf;

	if (!(buf = malloc(60)))
		return NULL;

	if (format & FMT_NUMERIC) {
		snprintf(buf, 60, "%s:%u", inet_ntoa(*addr), port);
	} else {
		snprintf(buf, 60, "%s:%s", addr_to_anyname(addr),
			 port_to_anyname(port, proto));
	}

	return buf;
}


/*
 * Get IP address and port from the argument.
 * Return 0 if failed,
 *	  1 if addr read
 *        2 if addr and port read
 */
int
parse_addrport(char *buf, u_int16_t proto, u_int32_t * addr,
	       u_int16_t * port)
{
	char *pp;
	long prt;
	struct in_addr inaddr;

	pp = strchr(buf, ':');
	if (pp)
		*pp = '\0';

	if (inet_aton(buf, &inaddr) != 0)
		*addr = inaddr.s_addr;
	else if (host_to_addr(buf, &inaddr) != -1)
		*addr = inaddr.s_addr;
	else
		return 0;

	if (pp == NULL)
		return 1;

	if ((prt = string_to_number(pp + 1, 0, 65535)) != -1)
		*port = htons(prt);
	else if ((prt = service_to_port(pp + 1, proto)) != -1)
		*port = htons(prt);
	else
		return 0;

	return 2;
}
