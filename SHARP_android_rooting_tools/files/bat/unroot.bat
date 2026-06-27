@echo off
set PATH="..\adb\";%PATH%
:CHECK
echo このスクリプトでunrootした場合、root権限を再奪取するまで /system の変更ができなくなります
echo 事前に /system の変更分を元に戻してください
echo.
set CHECK=
set /p CHECK=続行する場合は'yes'、終了する場合は'no'と入力してEnterを押してください:
if /i "%CHECK%"=="YES" goto :DELETE
goto :EXITBAT


:DELETE
echo unrootを行います
echo なお、SuperSUからroot権限の許可を求められる場合がありますので、その場合は端末で許可してください
echo 処理途中に自動で再起動します
pause

adb push ..\sh\unroot.sh /data/local/tmp/
adb shell chmod 755 /data/local/tmp/unroot.sh
adb shell su -c "/data/local/tmp/unroot.sh"
echo.
echo 正常に起動すればunroot完了です
echo.
echo メニュー画面に戻ります
pause
goto :EXITBAT


:EXITBAT
ping localhost -n 1 > nul
cls
call menu.bat