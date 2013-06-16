#ifndef _HELPER_H
#define _HELPER_H

/* printing format flags */
#define FMT_NONE	0x0000
#define FMT_NUMERIC	0x0001

/* various parsing helpers & parsing functions */
extern int string_to_number(const char *s, int min, int max);
extern int host_to_addr(const char *name, struct in_addr *addr);
extern char *addr_to_host(struct in_addr *addr);
extern char *addr_to_anyname(struct in_addr *addr);
extern int service_to_port(const char *name, unsigned short proto);
extern char *port_to_service(unsigned int port, unsigned short proto);
extern char *port_to_anyname(unsigned int port, unsigned short proto);
extern char *addrport_to_anyname(struct in_addr *addr, unsigned int port,
				 unsigned short proto,
				 unsigned int format);
extern int parse_addrport(char *buf, u_int16_t proto, u_int32_t * addr,
			  u_int16_t * port);

#endif				/* _HELPER_H */
