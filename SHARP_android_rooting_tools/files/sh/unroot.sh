#!/system/bin/sh
id

echo unroot start...
sleep 5

pm uninstall eu.chainfire.supersu
pm uninstall com.android.vpndialogs

echo remount /system...
sleep 5

mount -o rw,remount /system /system
rm -r /system/bin/.ext
rm /system/xbin/busybox
rm /system/xbin/su
mount -o ro,remount /system /system
rm /data/dalvik-cache/*.dex
sync;sync;sync;

echo rebooting system...
reboot