@echo off
set TITLE=SHARP_android_rooting_tools ver.7.0
set DAY=2014/06/22
set PATH="files\adb\";%PATH%
echo %TITLE% %DAY%
echo.
echo ADB および 端末のUSB接続 を確認します

adb kill-server
ping localhost -n 1 > nul
adb start-server
ping localhost -n 1 > nul
adb shell exit

if %ERRORLEVEL%==0 goto :CHECK

echo ...NG
echo.
echo 携帯端末とのADB USB接続が確認できませんでした
echo 携帯端末とUSBケーブルで接続し、
echo 「設定」→「開発者向けオプション」→「USBデバッグ」を有効にしてください
echo ADB USB ドライバは下記のURLより取得してください
echo https://sh-dev.sharp.co.jp/android/modules/driver/#adbAll
echo.
goto :EXITBAT


:CHECK
echo ...OK
ping localhost -n 1 > nul

:CHECK1
cls
echo %TITLE% %DAY%
echo.
echo このスクリプトを実行することによりあなたの携帯端末が文鎮化するリスクを伴います
echo また、メーカーの保証/サポート対象外になる可能性があります
echo あなたの自己責任の下に行い、問題発生時も自己解決を行ってください
echo 「設定」→「開発者向けオプション」から、「端末をスリープモードにしない」を有効にしてください
echo 「設定」→「外部接続」→「USB接続」から接続モードを「MTPモード」以外にしてください(カードリーダーモード推奨)
echo.

set CHECK1=
set /p CHECK1=続行する場合は'yes'、終了する場合は'no'と入力してEnterを押してください:
if /i "%CHECK1%"=="YES" goto :MENU
if /i "%CHECK1%"=="NO" goto :EXITBAT
goto :CHECK1


:MENU
ping localhost -n 1 > nul
cls

cd files\bat\
call menu.bat


:EXITBAT
cls
echo %TITLE% %DAY%
echo.
echo 終了します
ping localhost -n 2 > nul

adb kill-server
exit
