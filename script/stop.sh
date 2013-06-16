#/bin/bash

userspace/tcpvsadm --stop -i web2
userspace/tcpvsadm --stop -i web1
echo 1 > /proc/sys/net/ktcpvs/unload
echo Waiting...
sleep 3
rmmod tvs_hhttp
rmmod tvs_chttp
rmmod tvs_phttp
rmmod tvs_http
rmmod ktcpvs
