#/bin/bash

modprobe ktcpvs
modprobe tvs_http
modprobe tvs_phttp
modprobe tvs_chttp
modprobe tvs_hhttp
#echo 5 > /proc/sys/net/ktcpvs/debug_level
userspace/tcpvsadm -f config
userspace/tcpvsadm --start -i web1
userspace/tcpvsadm --start -i web2
