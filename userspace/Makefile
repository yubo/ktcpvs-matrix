#
#   Makefile for KTCPVS userspace utility (tcpvsadm)
#
#   Version: $Id: Makefile,v 1.5 2003/02/25 13:53:38 wensong Exp $
#
#   Authors: Wensong Zhang <wensong@linux-vs.org>
#

NAME	= tcpvsadm
VERSION	= $(shell cat VERSION)
RELEASE	= 1
SCHEDULERS = "$(shell cat SCHEDULERS)"

CC	= gcc
CFLAGS	= -Wall -Wunused -Wstrict-prototypes -g -O2
SBIN    = $(BUILD_ROOT)/sbin
MANDIR	= $(BUILD_ROOT)/usr/man
MAN     = $(MANDIR)/man8
MKDIR   = mkdir
INSTALL = install
INCLUDE = -I/usr/src/linux/include -I.. -I.
STATIC_LIBS = libtcpvs/libtcpvs.a


#####################################
# No servicable parts below this line

OBJS = tcpvsadm.o helper.o tcpvs_config.o
LIBS = $(POPT_LIB)
DEFINES = -DVERSION=\"$(VERSION)\" -DSCHEDULERS=\"$(SCHEDULERS)\"

.PHONY = all clean install dist distclean rpm rpms

all:            tcpvsadm

tcpvsadm:	$(OBJS) $(STATIC_LIBS)
		$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

install:        tcpvsadm
		strip tcpvsadm
		if [ ! -d $(SBIN) ]; then $(MKDIR) -p $(SBIN); fi
		$(INSTALL) -m 0755 tcpvsadm $(SBIN)
		if [ ! -d $(MAN) ]; then $(MKDIR) -p $(MAN); fi
		$(INSTALL) -m 0644 tcpvsadm.8 $(MAN)

clean:
		rm -f tcpvsadm $(NAME).spec $(NAME)-$(VERSION).tar.gz
		rm -rf debian/tmp
		find . -name '*.[ao]' -o -name "*~" -o -name "*.orig" \
		  -o -name "*.rej" -o -name core | xargs rm -f

distclean:	dist

dist:		clean
		sed -e "s/@@VERSION@@/$(VERSION)/g" \
		    -e "s/@@RELEASE@@/$(RELEASE)/g" \
		    < tcpvsadm.spec.in > tcpvsadm.spec
		( cd .. ; ln -sf userspace $(NAME)-$(VERSION);	\
		  tar czvf $(NAME)-$(VERSION).tar.gz		\
			--exclude CVS				\
			--exclude $(NAME)-$(VERSION).tar.gz	\
			$(NAME)-$(VERSION)/*;			\
		  mv $(NAME)-$(VERSION).tar.gz userspace;	\
		  rm -f $(NAME)-$(VERSION); )

rpm:		rpms

rpms:		dist
		cp $(NAME)-$(VERSION).tar.gz /usr/src/redhat/SOURCES/
		cp $(NAME).spec /usr/src/redhat/SPECS/
		(cd /usr/src/redhat/SPECS/ ; rpm -ba $(NAME).spec)

%.o:	%.c
		$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -o $@ -c $<

include $(shell echo */Makefile)
