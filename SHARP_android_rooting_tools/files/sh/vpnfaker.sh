#!/system/bin/sh
echo VpnFaker install...
id
sleep 5
stop zygote

sleep 5
busybox tar zxf /data/local/tmp/VpnFakerV2.tar.gz -C /data/local/tmp
busybox cp -p /data/system/packages.xml /data/system/packages.xml-
busybox cp -p /data/system/packages.list /data/system/packages.list-
busybox cp -p /data/system/packages.xml /data/local/tmp/packages_`date +%Y_%m_%d_%H_%M`.xml
busybox cp -p /data/system/packages.list /data/local/tmp/packages_`date +%Y_%m_%d_%H_%M`.list
busybox sed -f /data/local/tmp/packages.xml.sed /data/system/packages.xml- > /data/system/packages.xml
chown system.system /data/system/packages.xml
chmod 660 /data/system/packages.xml

sleep 5
busybox cp -p /data/local/tmp/VpnFaker.apk /data/app/VpnFaker.apk
chown system.system /data/app/VpnFaker.apk
chmod 644 /data/app/VpnFaker.apk

sleep 5
start zygote