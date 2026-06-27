@echo off
echo これから各SHデバイスのroot化を行います
echo root化に失敗すると文鎮化しますので、必ず自己責任の上で行って下さい
set PATH="..\adb\";%PATH%
pause

echo.
echo 必要なファイルの転送を行います
pause

adb push ..\bin\unlock_mmc_protect /data/local/tmp/
adb shell chmod 755 /data/local/tmp/unlock_mmc_protect
adb push ..\bin\unlock_lsm_miyabi /data/local/tmp/
adb shell chmod 755 /data/local/tmp/unlock_lsm_miyabi
adb push ..\bin\install_backdoor /data/local/tmp/
adb shell chmod 755 /data/local/tmp/install_backdoor
adb push ..\bin\run_root_shell /data/local/tmp/
adb shell chmod 755 /data/local/tmp/run_root_shell
adb push ..\bin\get_essential_address /data/local/tmp/
adb shell chmod 755 /data/local/tmp/get_essential_address
adb push ..\bin\su /data/local/tmp/
adb shell chmod 755 /data/local/tmp/su
adb push ..\bin\busybox /data/local/tmp/
adb shell chmod 755 /data/local/tmp/busybox

adb push ..\etc\SuperSU.apk /data/local/tmp/
adb shell chmod 755 /data/local/tmp/SuperSU.apk
adb push ..\etc\VpnFakerV2.tar.gz /data/local/tmp
adb shell chmod 777 /data/local/tmp/VpnFakerV2.tar.gz
adb push ..\etc\device.db /data/local/tmp
adb shell chmod 777 /data/local/tmp/device.db

adb push ..\sh\onBoot /data/local/tmp/
adb shell chmod 755 /data/local/tmp/onBoot
adb push ..\sh\getroot.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/getroot.sh
adb push ..\sh\vpnfaker.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/vpnfaker.sh
adb push ..\sh\recovery.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/recovery.sh

echo.
echo 必要なファイルの転送が終了しました
echo.
pause
goto :GETROOT


:GETROOT
echo root権限の奪取を行います
echo 指示があるまで端末を操作しないでください
pause

adb shell cd /data/local/tmp ; /data/local/tmp/run_root_shell -c "/data/local/tmp/getroot.sh"
echo.
echo root権限の奪取が完了しました
echo.
pause
echo SuperSU.apkをインストールします
echo.
adb shell pm install -t -f -r /data/local/tmp/SuperSU.apk
adb shell rm /data/local/tmp/SuperSU.apk
adb shell rm /data/local/tmp/su
echo.
echo SuperSU.apkのインストールが完了しました
echo アプリ一覧にSuperSUが追加されているか確認してください
echo SuperSUを起動し、必要に応じてsuバイナリのアップデートを行ってください
echo.
pause

echo 再起動を行います
echo しばらくお待ちください
adb reboot
echo.
echo メニュー画面に戻ります
pause
goto :EXITBAT


:EXITBAT
ping localhost -n 1 > nul
cls
call menu.bat