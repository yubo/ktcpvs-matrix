#ifndef _LIBTCPVS_H
#define _LIBTCPVS_H

#ifdef HAVE_NET_TCP_VS_H
#include <net/tcp_vs.h>
#else
#include "tcp_vs.h"
#endif

/* tcpvs info variable */
extern struct tcp_vs_getinfo tcpvs_info;

/* init socket and get tcpvs info */
extern int tcpvs_init(void);

/* get the version number */
extern unsigned int tcpvs_version(void);

/* add/edit/del service */
extern int tcpvs_add_service(struct tcp_vs_ident *id,
			     struct tcp_vs_config *conf);
extern int tcpvs_edit_service(struct tcp_vs_ident *id,
			      struct tcp_vs_config *conf);
extern int tcpvs_del_service(struct tcp_vs_ident *id);

/* start/stop service */
int tcpvs_start_service(struct tcp_vs_ident *id);
int tcpvs_stop_service(struct tcp_vs_ident *id);

/* flush all the services */
extern int tcpvs_flush(void);

/* add/edit/del destination server */
extern int tcpvs_add_dest(struct tcp_vs_ident *id,
			  struct tcp_vs_dest_u *dest);
extern int tcpvs_edit_dest(struct tcp_vs_ident *id,
			   struct tcp_vs_dest_u *dest);
extern int tcpvs_del_dest(struct tcp_vs_ident *id,
			  struct tcp_vs_dest_u *dest);

/* add/delete rule */
extern int tcpvs_add_rule(struct tcp_vs_ident *id,
			  struct tcp_vs_rule_u *rule);
extern int tcpvs_del_rule(struct tcp_vs_ident *id,
			  struct tcp_vs_rule_u *rule);

/* get tcpvs service */
extern struct tcp_vs_service_u *tcpvs_get_service(struct tcp_vs_ident *id);

/* get all the tcpvs services */
extern struct tcp_vs_get_services *tcpvs_get_services(void);

/* get the destination array of the specified service */
extern struct tcp_vs_get_dests *tcpvs_get_dests(struct tcp_vs_service_u
						*svc);

/* get the rule array of the specified service */
extern struct tcp_vs_get_rules *tcpvs_get_rules(struct tcp_vs_service_u
						*svc);

/* close the socket */
extern void tcpvs_close(void);

extern const char *tcpvs_strerror(int err);

#endif				/* _LIBTCPVS_H */
