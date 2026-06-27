#!/system/bin/sh
echo getroot start...
id
sleep 3

cd /data/local/tmp
./get_essential_address
./install_backdoor
./unlock_lsm_miyabi
./unlock_mmc_protect

echo remount /system...

mount -o rw,remount /system /system
cat /data/local/tmp/su > /system/xbin/su
chown root.root /system/xbin/su
chmod 6755 /system/xbin/su
cat /data/local/tmp/busybox > /system/xbin/busybox
chown root.root /system/xbin/busybox
chmod 755 /system/xbin/busybox
mount -o ro,remount /system /system
sync;sync;sync;