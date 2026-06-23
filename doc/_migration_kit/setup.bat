@echo off
chcp 932 >nul
setlocal EnableExtensions

rem ===== ŠÇ—ŽÒ‚ÖŽ©ŒÈ¸Ši =====
net session >nul 2>&1
if %errorlevel% NEQ 0 (
  echo ŠÇ—ŽÒŒ ŒÀ‚ÅÄ‹N“®‚µ‚Ü‚·...
  powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "SRC=%~dp0"
echo ============================================================
echo  SD-MobileImpact ico (Windows 7 32bit)
echo  source: %SRC%
echo ============================================================

if not exist "%SRC%SD-MobileImpact" echo [chushi] SD-MobileImpact folder nashi. zip wo kaitou shita basho de jikkou. & pause & exit /b 1
if not exist "%SRC%SDApf"           echo [chushi] SDApf folder nashi. & pause & exit /b 1

set "PF=%ProgramFiles%"
set "CF=%CommonProgramFiles%"

echo.
echo [1/5] honki haichi to "%PF%\Panasonic\SD-MobileImpact"
xcopy "%SRC%SD-MobileImpact" "%PF%\Panasonic\SD-MobileImpact\" /E /I /Y /Q >nul

echo [2/5] kyoyu module haichi to "%CF%\Panasonic"
xcopy "%SRC%SDApf"  "%CF%\Panasonic\SDApf\"  /E /I /Y /Q >nul
xcopy "%SRC%SD-PML" "%CF%\Panasonic\SD-PML\" /E /I /Y /Q >nul
xcopy "%SRC%SDApp"  "%CF%\Panasonic\SDApp\"  /E /I /Y /Q >nul
del "%PF%\Panasonic\SD-MobileImpact\mirssom.dll.bak" >nul 2>&1
del "%PF%\Panasonic\SD-MobileImpact\mirssom.dll.disabled" >nul 2>&1

echo [3/5] registry import
reg import "%SRC%Panasonic_Win7_32bit.reg"

echo [4/5] VC++2005 runtime (gamen no shiji ni shitagatte kudasai)
"%PF%\Panasonic\SD-MobileImpact\vcredist_x86.exe"

echo [5/5] reader driver audsub install (gamen no shiji ni shitagatte kudasai)
"%PF%\Panasonic\SD-MobileImpact\instaudsub.exe"

echo.
echo ============================================================
echo  haichi kanryo!
echo  tsugi no sousa:
echo   1) VMware: Player ^> Removable Devices ^> BN-SDCMP3 wo Connect
echo      (moto microSD wo sashita mama)
echo   2) kanrisha jikkou:
echo      "%PF%\Panasonic\SD-MobileImpact\SD-MobileImpact.exe"
echo   3) one-seg ichiran ga dereba seikou -^> saisei wo capture
echo ============================================================
pause
