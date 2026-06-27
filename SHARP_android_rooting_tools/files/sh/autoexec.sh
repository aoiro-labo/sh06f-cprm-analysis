#!/system/bin/sh
/data/local/tmp/busybox mount -o rw,remount /
/data/local/tmp/busybox chmod 755 /sbin
/data/local/tmp/busybox cp -p /data/local/tmp/_su /sbin
/data/local/tmp/busybox chown 0.0 /sbin/_su
/data/local/tmp/busybox chmod 6755 /sbin/_su
/data/local/tmp/busybox cp -p /data/local/tmp/au /sbin
/data/local/tmp/busybox chown 0.0 /sbin/au
/data/local/tmp/busybox chmod 6755 /sbin/au
/data/local/tmp/busybox mount -o ro,remount /
