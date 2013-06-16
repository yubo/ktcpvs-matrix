# ktcpvs migrate to 2.6

ifneq ($(KERNELRELEASE),)
	ifdef CONFIG_MODVERSIONS
	EXTRA_CFLAGS := -DCONFIG_TCP_VS_DEBUG
	endif
	obj-m := ktcpvs.o tvs_hhttp.o tvs_phttp.o tvs_chttp.o tvs_http.o tvs_wlc.o tvs_yhttp.o
	LIBS := tcp_vs_sched.o tcp_vs_ctl.o misc.o redirect.o tcp_vs_srvconn.o tcp_vs_timer.o tcp_vs.o fault.o regex/regcomp.o 
	LIBS += regex/kernel.o regex/regfree.o
	ktcpvs-y := $(LIBS)
	
	RELIBS := regex/kernel.o regex/regexec.o regex/regfree.o
	tvs_hhttp-y := tcp_vs_hhttp.o  $(RELIBS)
	tvs_phttp-y := tcp_vs_phttp.o tcp_vs_http_parser.o tcp_vs_http_trans.o $(RELIBS)
	tvs_chttp-y := tcp_vs_chttp.o tcp_vs_http_parser.o tcp_vs_http_trans.o avl.o $(RELIBS)
	tvs_yhttp-y := tcp_vs_yhttp.o tcp_vs_http_parser.o tcp_vs_http_trans.o avl.o $(RELIBS)
	tvs_http-y := tcp_vs_http.o tcp_vs_http_parser.o tcp_vs_http_trans.o $(RELIBS)
	tvs_wlc-y := tcp_vs_wlc.o $(RELIBS)
else
# Set kerneldir
KERNELDIR := /lib/modules/$(shell uname -r)/build
TARGET := tcp_vs.ko

$(TARGET):
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules
install: $(TARGET)
	@sh install.sh
clean:
	@rm -fv *o *mod* .*.cmd
	@rm -rfv .tmp*
	@rm -fv regex/*o regex/.*.cmd
load:
	@insmod ktcpvs.ko
	@insmod tvs_hhttp.ko
	@/root/bin/tcpvsadm -f config/conftest
test:
	@insmod ktcpvs.ko
	@echo 12 >/proc/sys/net/ktcpvs/debug_level
	@insmod tvs_phttp.ko
	@/root/bin/tcpvsadm -f config/conftest
unload:
	@echo 1 >/proc/sys/net/ktcpvs/unload
	@sleep 2
	@rmmod tvs_hhttp
	@rmmod ktcpvs
endif


