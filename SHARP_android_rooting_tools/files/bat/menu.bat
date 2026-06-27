@echo off
set PATH="..\adb\";%PATH%
:CHECK2
cls
echo %TITLE% %DAY%
echo.

echo メニュー
echo 1. root(tethered)奪取
echo 2. root有効化＆nand,miyabi unlock
echo 3. VpnFaker インストール
echo 4. unroot
echo 5. VpnFaker導入失敗による起動ループからの復旧
echo Q. 終了
echo.

set CHECK2=
set /p CHECK2=実行したい操作を選択してEnterを押してください:
if /i "%CHECK2%"=="1" goto :GETROOT
if /i "%CHECK2%"=="2" goto :DOROOT
if /i "%CHECK2%"=="3" goto :VPNFAKER
if /i "%CHECK2%"=="4" goto :UNROOT
if /i "%CHECK2%"=="5" goto :RECOVERY
if /i "%CHECK2%"=="q" goto :EXITBAT

goto :CHECK2


:EXITBAT
echo.
echo 終了します
adb kill-server
ping localhost -n 1 > nul
exit


:GETROOT
ping localhost -n 1 > nul
cls
call getroot.bat


:DOROOT
ping localhost -n 1 > nul
cls
call doroot.bat


:VPNFAKER
ping localhost -n 1 > nul
cls
call vpnfaker.bat


:UNROOT
ping localhost -n 1 > nul
cls
call unroot.bat


:RECOVERY
ping localhost -n 1 > nul
cls
call recovery.bat