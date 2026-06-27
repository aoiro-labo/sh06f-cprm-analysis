@echo off
set PATH="..\adb\";%PATH%
echo.
echo suコマンドを有効にするため、nand,miyabiアンロックを行います
echo.
echo SuperSUからroot権限の許可を求められる場合があります
echo その場合は端末を操作し許可してください
pause

adb shell cd /data/local/tmp ; /data/local/tmp/onBoot
adb shell su -c "id"
echo.
echo 画面にuid=0(root) gid=0(root)と表示されていればsuコマンドが有効になっています
echo.
echo メニュー画面に戻ります
pause
goto :EXITBAT

:EXITBAT
ping localhost -n 1 > nul
cls
call menu.bat