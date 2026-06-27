#!/system/bin/sh
echo device recovery...
id
sleep 5
stop zygote

sleep 5

rm /data/app/VpnFaker.apk
mv /data/system/packages.xml- /data/system/packages.xml
mv /data/system/packages.list- /data/system/packages.list
chown system.system /data/system/packages.xml
chmod 660 /data/system/packages.xml

rm /data/dalvik-cache/*.dex
sync;sync;sync;
sleep 5

start zygote