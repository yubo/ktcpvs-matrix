# ktcpvs-matrix 简介
===============

Stands for Kernel TCP Virtual Server, 在[KTCPVS][]基础上开发，可以在 hosts-apps两个维度上设置权值

读书的时候，导师的课题有需求，所有就有了这个软件，写于2008年，基于红帽子rhel4.0(linux-2.6.9)，整理硬盘翻出来的，也许有人会需要

## 简单介绍

  * demo/eapac.exe 演示录像
  * script/*       脚本工具
  * userspace/     用户工具

## 相关文章
===============

  * Xuanhua Shi, Hongbo Jiang, Ligang He, Hai Jin, Chonggang Wang, Bo Yu, Xueguang Chen, "[Developing an Optimized Application Hosting Framework in Clouds][EAPAC-CSE]", Journal of Computer and System Sciences, DOI: 10.1016/j.jcss.2013.02.003, 2013

  * Xuanhua Shi, Hongbo Jiang, Ligang He, Hai Jin, Chonggang Wang, Bo Yu, Fei Wang, "[EAPAC: An Enhanced Application Placement Framework for Data Centers][apphosting-jcss]", The 14th IEEE International Conference on Computational Science and Engineering, 2011

## 资源
===============

* [KTCPVS][]
* [EAPAC-CSE][]
* [apphosting-jcss][]

[KTCPVS]:http://www.linuxvirtualserver.org/software/ktcpvs/ktcpvs.html
[ktcpvs_img]:http://www.linuxvirtualserver.org/software/ktcpvs/ktcpvs_impl.jpg
[EAPAC-CSE]http://grid.hust.edu.cn/xhshi/paper/EAPAC-CSE.pdf "EAPAC: An Enhanced Application Placement Framework for Data Centers"
[apphosting-jcss]:http://grid.hust.edu.cn/xhshi/paper/apphosting-jcss.pdf "Developing an Optimized Application Hosting Framework in Clouds"




KTCPVS


What is it?
-----------

KTCPVS stands for Kernel TCP Virtual Server. It implements
application-level load balancing inside the Linux kernel, so called
Layer-7 switching. Although the scalability of KTCPVS is lower than
that of IPVS (IP Virtual Server), it is flexible, because the content
of request is known before the request is redirected to one server.


The Latest Version
------------------

Details of the latest version can be found on the Linux Virtual Server
project page under http://www.linuxvirtualserver.org/.


COPYRIGHT
---------

Copyright (c) 2001-2003 Wensong Zhang. It is released under GNU GPL
(General Public License). Please see the file called COPYING.


SETUP
-----

KTCPVS currently requires that your system is running the Linux kernel
2.4.x.

To build and insert the ipvs modules, the commands can be as follows:
	# build the modules
	cd <path-name>/ktcpvs
	make
	make -C userspace

	# insmod the modules and install ipvsadm
	su
	make install
	insmod ktcpvs_wlc.o
	insmod ktcpvs_http.o

	# set the debugging level
	echo 2 > /proc/sys/net/ktcpvs/debug_level
	
	# ktcpvs configuration
	userspace/tcpvsadm -A -i http -s http
	userspace/tcpvsadm -a -i http -r r1:80
	userspace/tcpvsadm -a -i http -r r2:80
	userspace/tcpvsadm -a -i http -r r3:80
	userspace/tcpvsadm --add-rule -i http --pattern=/images/.* -r r1:80
	userspace/tcpvsadm --add-rule -i http --pattern=/html/.* -r r2:80
	userspace/tcpvsadm --add-rule -i http --pattern=.* -r r3:80

	# list the configuration
	userspace/tcpvsadm --list

	# load configuration from file
	userspace/tcpvsadm -f <config-file>

	# flush all the configuration
	userspace/tcpvsadm -F

	# start/stop server
	userspace/tcpvsadm --start -i http
	userspace/tcpvsadm --stop -i http

	# remove modules
	echo 1 > /proc/sys/net/ktcpvs/unload
	rmmod ktcpvs_wlc
	rmmod ktcpvs_http
	rmmod ktcpvs

Note: please make sure that your running kernel image is built from
the Linux kernel 2.4.xx source under /usr/src/linux. If your Linux
kernel source is not under /usr/src/linux, you need make a symbolic
link /usr/src/linux to your kernel source or edit the ktcpvs Makefile
to specify the path of kernel source. If your running kernel image is
not built from your kernel source, you need to rebuild the running
kernel image with the IP Netfilter option enabled.
	

MAILING LIST
------------

There is a mailing list for the discussion of LVS and its
applications. It is open to anyone to join. I will announce new
versions on this list.

To join the mailing list, send mail with the word "subscribe" in the
Subject field to lvs-users-request@linuxvirtualserver.org.

To send mail to everyone on the list send it to
lvs-users@linuxvirtualserver.org.


FEEDBACK
--------

Send your comments, bug reports, bug fixes, and ideas to the LVS
mailing list or me.

Thanks,

Wensong Zhang
wensong@linux-vs.org

