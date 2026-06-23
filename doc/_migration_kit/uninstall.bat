@echo off
chcp 932 >nul
setlocal EnableExtensions

rem ===== kanrisha he jiko shoukaku =====
net session >nul 2>&1
if %errorlevel% NEQ 0 (
  echo kanrisha kengen de saikidou shimasu...
  powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo ============================================================
echo  SD-MobileImpact UNINSTALL (moto ni modosu)
echo ============================================================
set "PF=%ProgramFiles%"
set "CF=%CommonProgramFiles%"

echo [1/3] folder sakujo...
rmdir /s /q "%PF%\Panasonic\SD-MobileImpact"  2>nul
rmdir /s /q "%CF%\Panasonic\SDApf"   2>nul
rmdir /s /q "%CF%\Panasonic\SD-PML"  2>nul
rmdir /s /q "%CF%\Panasonic\SDApp"   2>nul
rmdir "%PF%\Panasonic" 2>nul
rmdir "%CF%\Panasonic" 2>nul

echo [2/3] registry sakujo...
reg delete "HKLM\SOFTWARE\Panasonic\SDApf"          /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Panasonic\SD-MobileImpact" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Panasonic"                /f >nul 2>&1
reg delete "HKCU\Software\CNC\SD-MobileImpact"       /f >nul 2>&1

echo [3/3] kanryo.
echo.
echo NOTE: VC++2005 runtime to audsub driver wa nokotte imasu.
echo  - VC++: Control Panel ^> Programs ^> "Microsoft Visual C++ 2005" wo sakujo
echo  - audsub: Device Manager kara sakujo (mataha sonomama de mo gai nashi)
echo ============================================================
pause
