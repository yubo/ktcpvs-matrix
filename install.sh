
DIR=/lib/modules/`uname -r`/kernel/net/ktcpvs/
if [ -d $DIR ]; then
	cp -f *ko  $DIR
else
	mkdir $DIR && cp -f *ko $DIR
fi
echo "Updating module dependencies"
depmod -a
echo "Done."
echo -n "Adding start script .. "
if [ -r /etc/redhat-release ]; then
	if cp script/ktcpvs /etc/init.d/ && chkconfig --add ktcpvs; then
		echo "OK ;)"
	else 
		echo Failed
	fi
else
	echo "start script only support redhat system now"
fi
