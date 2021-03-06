/*
 * tcpvs_config.c: parsing the tcpvs configuration file
 *
 * Version:	$Id: tcpvs_config.c,v 1.4.2.1 2004/10/30 16:28:14 wensong Exp $
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
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcpvs_config.h"
#include "helper.h"


#define FAIL(msg...)				\
    do {					\
	    fprintf(stderr, msg);		\
	    exit(1);				\
    } while (0)

#define GET_TOKEN(cf)				\
    do {					\
	    if (get_next_token(cf))		\
		    return -1;			\
    } while (0)

#define GET_EQUAL_TOKEN(cf);					\
    do {							\
	    if (get_next_token(cf))				\
		    return -1;					\
	    if (cf->token[0] != '=' || strlen(cf->token) != 1)	\
		    return -1;					\
    } while (0)


#define MAX_STRING_LEN 512
struct configfile {
	char *name;
	FILE *fp;
	char line[MAX_STRING_LEN];
	char *position;
	char *lineEnd;
	int lineNum;
	char token[MAX_STRING_LEN];
	int token_handled;
};

static struct configfile *
open_configfile(const char *filename)
{
	struct configfile *cf;

	if (!(cf = malloc(sizeof(*cf))))
		FAIL("no memory\n");

	cf->name = strdup(filename);
	if (!(cf->fp = fopen(filename, "r")))
		FAIL("config file %s opening error\n", filename);

	cf->position = cf->line;
	cf->lineEnd = cf->line;
	cf->lineNum = 1;

	return cf;
}

int
get_next_token(struct configfile *cf)
{
	char *p, *tp;
	char c;

	for (p = cf->position;; p++) {
		if (p >= cf->lineEnd) {
			if (!fgets(cf->line, MAX_STRING_LEN, cf->fp))
				return -1;
			p = cf->line;
			cf->lineEnd = cf->line + strlen(cf->line);
			cf->lineNum++;
		}

		c = *p;
		if (isspace(c))
			continue;

		if (c == '#') {
			p = cf->lineEnd;
			continue;
		}

		if (c == '\r' || c == '\n')
			continue;

		/* get token here */
		tp = cf->token;
		if (c == '"') {
			/* get a quoted string here */
			for (p++; *p != '"';) {
				c = *tp++ = *p++;
				if (c == '\\' && *p == '"')
					*tp++ = *p++;
				if (p >= cf->lineEnd)
					return -1;
			}
			p++;	/* skip the last quote symbol */
		} else {
			do {
				*tp++ = *p++;
			} while (!isspace(*p) && p < cf->lineEnd);
		}

		*tp = '\0';
		cf->token_handled = 0;
		cf->position = p;
		return 0;
	}
}

static inline int
feof_configfile(struct configfile *cf)
{
	return feof(cf->fp);
}

static void
close_configfile(struct configfile *cf)
{
	fclose(cf->fp);
	free(cf->name);
	free(cf);
}


struct parse_command {
	const char *name;
	int (*func) (struct configfile * cf, void *param);
	const char *errmsg;
};

static const char *errmsg = "no error";

static inline const struct parse_command *
find_command(const char *name, const struct parse_command *cmds)
{
	while (cmds->name) {
		if (!strcasecmp(name, cmds->name))
			return cmds;
		else
			++cmds;
	}
	return NULL;
}

static inline int
invoke_command(const struct parse_command *cmd,
	       struct configfile *cf, void *config)
{
	return cmd->func(cf, config);
}

static int
handle_command(struct configfile *cf, void *config,
	       const struct parse_command *cmds)
{
	const struct parse_command *cmd;

	if (get_next_token(cf))
		return 0;

	if ((cmd = find_command(cf->token, cmds))) {
		int result;

		if ((result = invoke_command(cmd, cf, config)))
			errmsg = cmd->errmsg;
		cf->token_handled = 1;
		return result;
	}

	return 0;
}


static int
parse_listen(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	if (parse_addrport(cf->token, IPPROTO_TCP,
			   &svc->conf.addr, &svc->conf.port) == 0)
		return -1;

	return 0;
}

static int
parse_scheduler(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	strncpy(svc->conf.sched_name, cf->token, KTCPVS_SCHEDNAME_MAXLEN);

	return 0;
}

static int
parse_startservers(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;
	int parse;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	if ((parse = string_to_number(cf->token, 1, 65535)) == -1)
		return -1;
	svc->conf.startservers = parse;

	return 0;
}

static int
parse_maxclients(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;
	int parse;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	if ((parse = string_to_number(cf->token, 1, 65535)) == -1)
		return -1;
	svc->conf.maxClients = parse;

	return 0;
}

static int
parse_minspareservers(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;
	int parse;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	if ((parse = string_to_number(cf->token, 1, 65535)) == -1)
		return -1;
	svc->conf.minSpareServers = parse;

	return 0;
}

static int
parse_maxspareservers(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;
	int parse;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	if ((parse = string_to_number(cf->token, 1, 65535)) == -1)
		return -1;
	svc->conf.maxSpareServers = parse;

	return 0;
}

static int
parse_redirect(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;

	GET_EQUAL_TOKEN(cf);

	GET_TOKEN(cf);
	if (parse_addrport(cf->token, IPPROTO_TCP,
			   &svc->conf.redirect_addr,
			   &svc->conf.redirect_port) == 0)
		return -1;

	return 0;
}

static int
parse_server(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;
	struct tcp_vs_dest_u *dest;
	int i;
	int parse;

	GET_EQUAL_TOKEN(cf);

	i = svc->num_dests++;
	svc->dests = realloc(svc->dests, sizeof(struct tcp_vs_dest_u) *
			     svc->num_dests);
	if (!svc->dests)
		FAIL("no memory\n");

	dest = svc->dests + i;
	memset(dest, 0, sizeof(struct tcp_vs_dest_u));

	GET_TOKEN(cf);
	if (parse_addrport(cf->token, IPPROTO_TCP,
			   &dest->addr, &dest->port) == 0)
		return -1;

	GET_TOKEN(cf);
	if ((parse = string_to_number(cf->token, 1, 65535)) == -1)
		return -1;
	dest->weight = parse;

	return 0;
}

static int
parse_rule(struct configfile *cf, void *param)
{
	struct tcpvs_service *svc = param;
	struct tcp_vs_rule_u *rule;
	int i;

	GET_EQUAL_TOKEN(cf);

	i = svc->num_rules++;
	svc->rules = realloc(svc->rules, sizeof(struct tcp_vs_rule_u) *
			     svc->num_rules);
	if (!svc->rules)
		FAIL("no memory\n");

	rule = svc->rules + i;
	memset(rule, 0, sizeof(struct tcp_vs_rule_u));

	GET_TOKEN(cf);
	if (strcasecmp(cf->token, "pattern"))
		return -1;

	GET_TOKEN(cf);
	strncpy(rule->pattern, cf->token, KTCPVS_PATTERN_MAXLEN);

	GET_TOKEN(cf);
	if (!strcasecmp(cf->token, "match")) {
		GET_TOKEN(cf);
		rule->match_num = string_to_number(cf->token, 0, 10);
		if (rule->match_num == -1) 
			rule->match_num = 0;
		GET_TOKEN(cf);
	}
	if (strcasecmp(cf->token, "use"))
		return -1;

	GET_TOKEN(cf);
	if (strcasecmp(cf->token, "server"))
		return -1;

	GET_TOKEN(cf);
	if (parse_addrport(cf->token, IPPROTO_TCP,
			   &rule->addr, &rule->port) == 0)
		return -1;

	return 0;
}

static const struct parse_command servicecmds[] = {
	{"listen", parse_listen, "parsing listen address error"},
	{"scheduler", parse_scheduler, "parsing scheduler error"},
	{"startservers", parse_startservers, "parsing startservers error"},
	{"maxclients", parse_maxclients, "parsing maxclients error"},
	{"minspareservers", parse_minspareservers,
	 "parsing minspareservers error"},
	{"maxspareservers", parse_maxspareservers,
	 "parsing maxspareservers error"},
	{"redirect", parse_redirect, "parsing redirect address error"},
	{"server", parse_server, "parsing server error"},
	{"rule", parse_rule, "parsing rule error"},
	{NULL},
};

static int
parse_service(struct configfile *cf, void *param)
{
	struct tcpvs_config *config = param;
	struct tcpvs_service *svc;
	int i;

	i = config->num_services++;

	config->services = realloc(config->services,
				   sizeof(struct tcpvs_service) *
				   config->num_services);
	if (!config->services)
		FAIL("no memory\n");

	svc = config->services + i;
	memset(svc, 0, sizeof(struct tcpvs_service));

	if (get_next_token(cf))
		return -1;
	strncpy(svc->ident.name, cf->token, KTCPVS_IDENTNAME_MAXLEN);

	if (get_next_token(cf))
		return -1;
	if (cf->token[0] != '{' || strlen(cf->token) != 1)
		return -1;

	while (!(feof_configfile(cf))) {
		int result = handle_command(cf, svc, servicecmds);
		if (result)
			FAIL
			    ("Syntax error in the config file %s (line %d): "
			     "%s\n", cf->name, cf->lineNum, errmsg);
		if (!cf->token_handled)
			break;
	}
	if (cf->token[0] != '}')
		return -1;

	return 0;
}


static const struct parse_command globalcmds[] = {
	{"virtual", parse_service, "parse_service error"},
	{NULL},
};

int
tcpvs_parse_config(const char *filename, struct tcpvs_config *config)
{
	struct configfile *cf;

	memset(config, 0, sizeof(*config));

	if (!(cf = open_configfile(filename)))
		exit(1);

	while (!(feof_configfile(cf))) {
		int result = handle_command(cf, config, globalcmds);
		if (result)
			FAIL
			    ("Syntax error in the config file %s (line %d): "
			     "%s\n", cf->name, cf->lineNum, errmsg);
		if (!cf->token_handled)
			FAIL("invalid command %s\n", cf->token);
	}

	close_configfile(cf);

	return 0;
}
