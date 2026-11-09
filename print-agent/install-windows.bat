@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Invora Print Station - setup

rem --- needs administrator rights to install a Windows service ---
net session >nul 2>&1
if errorlevel 1 (
  echo Asking for administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

where python >nul 2>&1
if errorlevel 1 (
  echo.
  echo Python was not found. Install Python 3.9+ from https://www.python.org/downloads/
  echo and tick "Add Python to PATH" during setup, then run this file again.
  pause
  exit /b 1
)

echo [1/4] Installing required packages...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt
if errorlevel 1 goto fail
python -m pywin32_postinstall -install >nul 2>&1

echo [2/4] Removing an older service (if any)...
python agent.py stop >nul 2>&1
python agent.py remove >nul 2>&1

echo [3/4] Installing the Windows service "Invora Print Station" (starts automatically with Windows)...
python agent.py --startup auto install
if errorlevel 1 goto task
sc failure InvoraPrint reset= 86400 actions= restart/5000/restart/5000/restart/30000 >nul 2>&1

echo [4/4] Starting the service...
python agent.py start
if errorlevel 1 goto task
echo.
echo Done. The print station runs as a Windows service and starts by itself after every restart.
echo Settings page: http://localhost:8766
start "" http://localhost:8766
pause
exit /b 0

:task
echo.
echo The service could not be installed or started. Using "start at logon" instead...
schtasks /Create /TN "Invora Print Station" /TR "\"%~dp0run-windows.bat\"" /SC ONLOGON /RL HIGHEST /F
call "%~dp0run-windows.bat"
timeout /t 4 >nul
start "" http://localhost:8766
pause
exit /b 0

:fail
echo.
echo Installing packages failed. Check the internet connection and run this file again.
pause
exit /b 1
