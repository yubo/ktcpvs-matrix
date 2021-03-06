/*
 * KTCPVS  -    Kernel TCP Virtual Server
 *
 * Copyright (C) 2001, Wensong Zhang <wensong@gnuchina.org>
 *
 * tcp_vs.h: main structure definitions and function prototypes
 *
 * $Id: tcp_vs.h,v 1.21.2.3 2004/12/17 17:39:48 wensong Exp $
 *
 */

#ifndef _TCP_VS_H
#define _TCP_VS_H
#define M_THREAD_NAME "KTCPVS Master"
#define D_THREAD_NAME "KTCPVS D"
#define C_THREAD_NAME "KTCPVS C"

#include <asm/types.h>		/* For __uXX types */

#define TCP_VS_VERSION_CODE		0x000012
#define NVERSION(version)                       \
	(version >> 16) & 0xFF,                 \
	(version >> 8) & 0xFF,                  \
	version & 0xFF

#define KTCPVS_IDENTNAME_MAXLEN		16
#define KTCPVS_SCHEDNAME_MAXLEN		16
#define KTCPVS_PATTERN_MAXLEN           256

/*
 *      KTCPVS socket options
 */
#define TCP_VS_BASE_CTL		(64+1024+64+64)	/* base */

#define TCP_VS_SO_SET_NONE	TCP_VS_BASE_CTL	/* just peek */
#define TCP_VS_SO_SET_ADD	(TCP_VS_BASE_CTL+1)
#define TCP_VS_SO_SET_EDIT	(TCP_VS_BASE_CTL+2)
#define TCP_VS_SO_SET_DEL	(TCP_VS_BASE_CTL+3)
#define TCP_VS_SO_SET_FLUSH	(TCP_VS_BASE_CTL+4)
#define TCP_VS_SO_SET_LIST	(TCP_VS_BASE_CTL+5)
#define TCP_VS_SO_SET_ADDDEST	(TCP_VS_BASE_CTL+6)
#define TCP_VS_SO_SET_DELDEST	(TCP_VS_BASE_CTL+7)
#define TCP_VS_SO_SET_EDITDEST	(TCP_VS_BASE_CTL+8)
#define TCP_VS_SO_SET_ADDRULE	(TCP_VS_BASE_CTL+9)
#define TCP_VS_SO_SET_DELRULE	(TCP_VS_BASE_CTL+10)
#define TCP_VS_SO_SET_START	(TCP_VS_BASE_CTL+11)
#define TCP_VS_SO_SET_STOP	(TCP_VS_BASE_CTL+12)
#define TCP_VS_SO_SET_MAX	TCP_VS_SO_SET_STOP

#define TCP_VS_SO_GET_VERSION	TCP_VS_BASE_CTL
#define TCP_VS_SO_GET_INFO	(TCP_VS_BASE_CTL+1)
#define TCP_VS_SO_GET_SERVICES	(TCP_VS_BASE_CTL+2)
#define TCP_VS_SO_GET_SERVICE	(TCP_VS_BASE_CTL+3)
#define TCP_VS_SO_GET_DESTS	(TCP_VS_BASE_CTL+4)
#define TCP_VS_SO_GET_DEST	(TCP_VS_BASE_CTL+5)	/* not used now */
#define TCP_VS_SO_GET_RULES	(TCP_VS_BASE_CTL+6)
#define TCP_VS_SO_GET_MAX	TCP_VS_SO_GET_RULES


#define TCP_VS_TEMPLATE_TIMEOUT 15*HZ


struct tcp_vs_ident {
	char name[KTCPVS_IDENTNAME_MAXLEN];
};

struct tcp_vs_config {
	/* the IP address and/or port to which the server listens */
	__u32 addr;
	__u16 port;

	/* scheduler name */
	char sched_name[KTCPVS_SCHEDNAME_MAXLEN];

	unsigned timeout;	/* timeout in ticks */
	int startservers;
	int maxSpareServers;
	int minSpareServers;

	/* the max number of servers running */
	int maxClients;
	int keepAlive;
	int maxKeepAliveRequests;
	int keepAliveTimeout;

	/* address/port to redirect */
	__u32 redirect_addr;
	__u16 redirect_port;
};


struct tcp_vs_dest_u {
	__u32 addr;		/* IP address of real server */
	__u16 port;		/* port number of the service */
	int weight;		/* server weight */
	__u32 conns;		/* active connections */
};


struct tcp_vs_rule_u {
	/* rule pattern */
	int type;
	char pattern[KTCPVS_PATTERN_MAXLEN];
	size_t len;

	/* destination server */
	__u32 addr;
	__u16 port;

	/* special entry for hhttp module */
	int match_num;
};


/* The argument to TCP_VS_SO_GET_INFO */
struct tcp_vs_getinfo {
	/* version number */
	unsigned int version;

	/* number of virtual services */
	unsigned int num_services;
};

/* The argument to TCP_VS_SO_GET_SERVICE */
struct tcp_vs_service_u {
	/* server ident */
	struct tcp_vs_ident ident;

	/* server configuration */
	struct tcp_vs_config conf;

	/* number of real servers */
	unsigned int num_dests;

	/* number of rules */
	unsigned int num_rules;

	/* run-time variables */
	unsigned int conns;	/* connection counter */
	unsigned int running;	/* running flag */
};

/* The argument to TCP_VS_SO_GET_SERVICES */
struct tcp_vs_get_services {
	/* number of virtual services */
	unsigned int num_services;

	/* service table */
	struct tcp_vs_service_u entrytable[0];
};

/* The argument to TCP_VS_SO_GET_DESTS */
struct tcp_vs_get_dests {
	/* server ident */
	struct tcp_vs_ident ident;

	/* number of real servers */
	unsigned int num_dests;

	/* real server table */
	struct tcp_vs_dest_u entrytable[0];
};

/* The argument to TCP_VS_SO_GET_RULES */
struct tcp_vs_get_rules {
	/* server ident */
	struct tcp_vs_ident ident;

	/* number of real servers */
	unsigned int num_rules;

	/* real server table */
	struct tcp_vs_rule_u entrytable[0];
};


#ifdef __KERNEL__

#include <linux/list.h>		/* for list_head */
#include <linux/spinlock.h>	/* for rwlock_t */
#include <asm/atomic.h>		/* for atomic_t */
#include <linux/sysctl.h>	/* for ctl_table */
#include <linux/slab.h>		/* for kmalloc */

#include "regex/regex.h"


#ifdef CONFIG_TCP_VS_DEBUG
extern int tcp_vs_get_debug_level(void);
#define TCP_VS_DBG(level, msg...)			\
    do {						\
	    if (level <= tcp_vs_get_debug_level())	\
		    printk(KERN_DEBUG "TCPVS: " msg);	\
    } while (0)
#else				/* NO DEBUGGING at ALL */
#define TCP_VS_DBG(level, msg...)  do {} while (0)
#endif

#define TCP_VS_ERR(msg...) printk(KERN_ERR "TCPVS: " msg)
#define TCP_VS_INFO(msg...) printk(KERN_INFO "TCPVS: " msg)
#define TCP_VS_WARNING(msg...) \
	printk(KERN_WARNING "TCPVS: " msg)
#define TCP_VS_ERR_RL(msg...)				\
    do {						\
	    if (net_ratelimit())			\
		    printk(KERN_ERR "TCPVS: " msg);	\
    } while (0)

#ifdef CONFIG_TCP_VS_DEBUG
#define EnterFunction(level)						\
    do {								\
	    if (level <= tcp_vs_get_debug_level())			\
		    printk(KERN_DEBUG "Enter: %s, %s line %i\n",	\
			   __FUNCTION__, __FILE__, __LINE__);		\
    } while (0)
#define LeaveFunction(level)						\
    do {								\
	    if (level <= tcp_vs_get_debug_level())			\
			printk(KERN_DEBUG "Leave: %s, %s line %i\n",	\
			       __FUNCTION__, __FILE__, __LINE__);	\
    } while (0)
#else
#define EnterFunction(level)   do {} while (0)
#define LeaveFunction(level)   do {} while (0)
#endif

/* switch off assertions (if not already off) */
#ifdef CONFIG_TCP_VS_DEBUG
#define assert(expr)						\
	if(!(expr)) {						\
		printk( "Assertion failed! %s,%s,%s,line=%d\n",	\
		#expr,__FILE__,__FUNCTION__,__LINE__);		\
	}
#else
#define assert(expr) do {} while (0)
#endif


#define KTCPVS_CHILD_HARD_LIMIT		65536

#define NET_KTCPVS			20

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

enum {
	NET_KTCPVS_DEBUGLEVEL = 1,
	NET_KTCPVS_UNLOAD = 2,
	NET_KTCPVS_MAXBACKLOG = 3,
	NET_KTCPVS_ZEROCOPY_SEND = 4,
	NET_KTCPVS_KEEPALIVE_TIMEOUT = 5,
	NET_KTCPVS_READ_TIMEOUT = 6,
};


/*
 *	Slow timer for KTCPVS connections
 */
typedef struct slowtimer_struct {
	struct list_head list;
	unsigned long expires;
	unsigned long data;
	void (*function) (unsigned long);
} slowtimer_t;


struct tcp_vs_rule {
	struct list_head list;

	int type;
	char *pattern;
	size_t len;
	regex_t rx;

	struct list_head destinations;

	/* special field for hhttp module */
	int match_num;
};


/*
 *	The information about the KTCPVS service
 */
struct tcp_vs_service {
	/* virtual service list */
	struct list_head list;

	/* server ident */
	struct tcp_vs_ident ident;

	/* server configuration */
	struct tcp_vs_config conf;

	/* server scheduler */
	struct tcp_vs_scheduler *scheduler;	/* bound scheduler object */
	void *sched_data;	/* scheduler application data */

	/* real server list */
	struct list_head destinations;
	__u32 num_dests;

	/* rule list */
	struct list_head rule_list;
	__u32 num_rules;

	/* locking for the destination list and the rule list */
	rwlock_t lock;

	/* server control */
	int start;
	int stop;

	/* run-time variables */
	struct socket *mainsock;
	atomic_t conns;		/* connection counter */
	atomic_t childcount;	/* child counter */
	atomic_t running;	/* running flag */
};


/*
 *	The real server destination forwarding entry
 *	with ip address, port, weight ...
 */
typedef struct tcp_vs_dest {
	struct list_head n_list;	/* for dest list in its server */
	struct list_head r_list;	/* for dest list in rule */
	atomic_t refcnt;	/* reference counter */

	__u32 addr;		/* IP address of real server */
	__u16 port;		/* port number of the service */
	int weight;		/* server weight */
	unsigned flags;		/* dest status flags */
	atomic_t conns;		/* active connections */
	int active;		/* status of the destination */
} tcp_vs_dest_t;


typedef struct server_conn_struct {
	/* hash keys and list for collision resolution */
	__u32 addr;		/* IP address of the server */
	__u16 port;		/* port number of the server */
	struct list_head list;	/* d-linked list head for hashing */

	/* status flags */
	__u16 flags;

	/* socket connected to a destination server */
	struct socket *sock;
	struct tcp_vs_dest *dest;

	/* timer for keepalive connections */
	slowtimer_t keepalive_timer;
	unsigned long timeout;
	unsigned int nr_keepalives;
} server_conn_t;


/*
 *      TCPVS connection object
 */
struct tcp_vs_conn {
	struct list_head n_list;	/* d-linked list head */
	__u32 addr;		/* client address */
	unsigned flags;		/* status flag */

	struct socket *csock;	/* socket connected to client */
	struct socket *dsock;	/* socket connected to server */
	struct tcp_vs_dest *dest;	/* destination server */
	struct tcp_vs_service *svc;	/* service it belongs to */

	char *buffer;		/* buffer for conn handling */
	size_t buflen;		/* buffer length */
};


/*
 *	The scheduler object
 */
struct tcp_vs_scheduler {
	struct list_head n_list;	/* d-linked list head */
	char *name;		/* scheduler name */
	struct module *module;	/* THIS_MODULE/NULL */

	/* initializing the scheduling elements in the service  */
	int (*init_service) (struct tcp_vs_service * svc);
	/* releasing the scheduling elements in the service */
	int (*done_service) (struct tcp_vs_service * svc);
	/* updating the scheduling elements in the service */
	int (*update_service) (struct tcp_vs_service * svc);

	/* select a server and connect to it */
	int (*schedule) (struct tcp_vs_conn * conn,
			 struct tcp_vs_service * svc);
};


/*
 *	TCPVS service child
 */
struct tcp_vs_child {
	struct tcp_vs_service *svc;	/* service it belongs to */
	int pid;		/* pid of child */
	volatile __u16 status;	/* child status */
};


/* from misc.c */
extern int StartListening(struct tcp_vs_service *svc);
extern void StopListening(struct tcp_vs_service *svc);
extern struct socket *tcp_vs_connect2dest(tcp_vs_dest_t * dest);
extern int tcp_vs_sendbuffer(struct socket *sock, const char *buffer,
			     const size_t length, unsigned long flags);
extern int tcp_vs_recvbuffer(struct socket *sock, char *buffer,
			     const size_t buflen, unsigned long flags);
extern int tcp_vs_xmit(struct socket *sock, const char *buffer,
		       const size_t length, unsigned long flags);


#ifndef strdup
static __inline__ char *strdup(char *str)
{
	char *s;
	int n;

	if (str == NULL)
		return NULL;

	n = strlen(str) + 1;
	s = kmalloc(n, GFP_ATOMIC);
	if (!s)
		return NULL;
	return strcpy(s, str);
}
#endif

extern char *tcp_vs_getline(char *s, char *token, int n);
extern char *tcp_vs_getword(char *s, char *token, int n);

/* from tcp_vs_ctl.c */
extern struct list_head tcp_vs_svc_list;
extern rwlock_t __tcp_vs_svc_lock;
extern int sysctl_ktcpvs_unload;
extern int sysctl_ktcpvs_max_backlog;
extern int sysctl_ktcpvs_zerocopy_send;
extern int sysctl_ktcpvs_keepalive_timeout;
extern int sysctl_ktcpvs_read_timeout;

extern int tcp_vs_flush(void);
extern int tcp_vs_control_start(void);
extern void tcp_vs_control_stop(void);

/* from tcp_vs_sched.c */
extern int register_tcp_vs_scheduler(struct tcp_vs_scheduler *scheduler);
extern int unregister_tcp_vs_scheduler(struct tcp_vs_scheduler *scheduler);
extern int tcp_vs_bind_scheduler(struct tcp_vs_service *svc,
				 struct tcp_vs_scheduler *scheduler);
extern int tcp_vs_unbind_scheduler(struct tcp_vs_service *svc);
extern struct tcp_vs_scheduler *tcp_vs_scheduler_get(const char *name);
extern void tcp_vs_scheduler_put(struct tcp_vs_scheduler *sched);

/* from redirect.c */
extern int redirect_to_local(struct tcp_vs_conn *conn, __u32 addr,
			     __u16 port);
/* from fault.c */
extern int fault_redirect(struct tcp_vs_conn *conn, struct tcp_vs_service *svc);

/* from tcp_vs_srvconn.c */
extern server_conn_t *tcp_vs_srvconn_get(__u32 addr, __u16 port);
extern void tcp_vs_srvconn_put(server_conn_t * sc);
extern server_conn_t *tcp_vs_srvconn_new(tcp_vs_dest_t * dest);
extern void tcp_vs_srvconn_free(server_conn_t * sc);
extern int tcp_vs_srvconn_init(void);
extern void tcp_vs_srvconn_cleanup(void);

/* from tcp_vs_timer.c */
void assert_slowtimer(int pos);
extern void tcp_vs_add_slowtimer(slowtimer_t * timer);
extern int tcp_vs_del_slowtimer(slowtimer_t * timer);
extern void tcp_vs_mod_slowtimer(slowtimer_t * timer, unsigned long expires);
extern void tcp_vs_slowtimer_init(void);
extern void tcp_vs_slowtimer_cleanup(void);
extern void tcp_vs_slowtimer_collect(void);

static inline void
init_slowtimer(slowtimer_t * timer)
{
	timer->list.next = timer->list.prev = NULL;
}

static inline int
slowtimer_pending(const slowtimer_t * timer)
{
	return timer->list.next != NULL;
}

#endif				/* __KERNEL__ */

#endif				/* _TCP_VS_H */
