@echo off
chcp 932 >nul
setlocal EnableExtensions
rem === XP/Vista you kanni ban (jiko shoukaku nashi) ===
rem === XP wa kihon admin nanode sonomama jikkou. Vista/7 wa "kanrisha de jikkou" de hajimeru koto ===

set "SRC=%~dp0"
echo ============================================================
echo  SD-MobileImpact setup (XP/Vista you, kanrisha de jikkou suru koto)
echo  source: %SRC%
echo ============================================================
if not exist "%SRC%SD-MobileImpact" echo [chushi] SD-MobileImpact folder nashi. zip kaitou basho de jikkou. & pause & exit /b 1

set "PF=%ProgramFiles%"
set "CF=%CommonProgramFiles%"

echo [1/5] honki haichi...
xcopy "%SRC%SD-MobileImpact" "%PF%\Panasonic\SD-MobileImpact\" /E /I /Y /Q >nul
echo [2/5] kyoyu module haichi...
xcopy "%SRC%SDApf"  "%CF%\Panasonic\SDApf\"  /E /I /Y /Q >nul
xcopy "%SRC%SD-PML" "%CF%\Panasonic\SD-PML\" /E /I /Y /Q >nul
xcopy "%SRC%SDApp"  "%CF%\Panasonic\SDApp\"  /E /I /Y /Q >nul
del "%PF%\Panasonic\SD-MobileImpact\mirssom.dll.bak" >nul 2>&1
del "%PF%\Panasonic\SD-MobileImpact\mirssom.dll.disabled" >nul 2>&1
echo [3/5] registry import...
reg import "%SRC%Panasonic_Win7_32bit.reg"
echo [4/5] VC++2005 runtime...
"%PF%\Panasonic\SD-MobileImpact\vcredist_x86.exe"
echo [5/5] reader driver audsub...
"%PF%\Panasonic\SD-MobileImpact\instaudsub.exe"
echo.
echo kanryo! BN-SDCMP3 wo USB setsuzoku go, SD-MobileImpact.exe wo jikkou.
pause
