@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"
title Invora Print Station - setup

rem ---- administrator rights are needed to install a Windows service ----
net session >nul 2>&1
if errorlevel 1 (
  echo Asking for administrator rights...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo.
echo ================================================================
echo   Invora Print Station - setup
echo   A log of this setup is written to install.log
echo ================================================================
echo.
echo setup started %date% %time% > install.log

rem ---- find a real Python 3.9+ (the "py" launcher first; "python" may be the Microsoft Store shortcut) ----
set "PY="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" >nul 2>&1 && set "PY=py -3"
if not defined PY python -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" >nul 2>&1 && set "PY=python"
if not defined PY (
  echo Python 3.9 or newer was not found.
  echo  1. Install it from https://www.python.org/downloads/  and tick "Add Python to PATH".
  echo  2. If Python is installed but still not found: Windows Settings ^> Apps ^> Advanced app settings ^>
  echo     App execution aliases, and turn OFF "python.exe" and "python3.exe" ^(Microsoft Store shortcuts^).
  echo  3. Run this file again.
  echo no python >> install.log
  pause
  exit /b 1
)
for /f "delims=" %%v in ('%PY% -c "import sys;print(sys.version.split()[0])"') do set "PYV=%%v"
echo Python !PYV! found ^(%PY%^).
echo python %PY% !PYV! >> install.log

rem ---- pip itself ----
%PY% -m pip --version >nul 2>&1
if errorlevel 1 (
  echo pip is missing; installing it...
  %PY% -m ensurepip --upgrade >> install.log 2>&1
)

rem ---- already installed? (running setup again) ----
%PY% -c "import cryptography, PIL, pypdfium2, win32print" >nul 2>&1 && (
  echo [1/4] Required packages are already installed.
  goto pkgok
)

echo [1/4] Installing required packages. This needs the internet and can take a few minutes;
echo       progress is shown below. If the main server ^(pypi.org^) is slow or blocked,
echo       Iranian mirrors are tried automatically.
echo.
set "PIPOPT=--disable-pip-version-check --prefer-binary --no-input --timeout 25 --retries 2"

echo --- trying pypi.org ...
%PY% -m pip install %PIPOPT% -r requirements.txt
if not errorlevel 1 goto pkgok

for %%M in (https://mirror-pypi.runflare.com/simple https://package-mirror.liara.ir/repository/pypi/simple https://repo.hmirror.ir/python/simple https://pypi.tuna.tsinghua.edu.cn/simple) do (
  echo.
  echo --- trying mirror %%M ...
  echo mirror %%M >> install.log
  %PY% -m pip install %PIPOPT% -i %%M -r requirements.txt
  if not errorlevel 1 goto pkgok
)
goto fail

:pkgok
%PY% -c "import cryptography, PIL, pypdfium2, win32print" >> install.log 2>&1
if errorlevel 1 goto fail
echo Packages OK.
%PY% -m pywin32_postinstall -install -silent >> install.log 2>&1

echo.
echo [2/4] Removing an older service ^(if any^)...
%PY% agent.py stop >nul 2>&1
%PY% agent.py remove >nul 2>&1

echo [3/4] Installing the Windows service "Invora Print Station" ^(starts with Windows^)...
%PY% agent.py --startup auto install >> install.log 2>&1
if errorlevel 1 goto task
sc failure InvoraPrint reset= 86400 actions= restart/5000/restart/5000/restart/30000 >nul 2>&1

echo [4/4] Starting the service...
%PY% agent.py start >> install.log 2>&1
if errorlevel 1 goto task
timeout /t 3 >nul
echo.
echo Done. The print station runs as a Windows service and starts by itself after every restart.
echo Settings page: http://localhost:8766
echo done service >> install.log
start "" http://localhost:8766
pause
exit /b 0

:task
echo.
echo The Windows service could not be installed or started ^(details in install.log^).
echo Using "start when I log in to Windows" instead...
schtasks /Create /TN "Invora Print Station" /TR "\"%~dp0run-windows.bat\"" /SC ONLOGON /RL HIGHEST /F >> install.log 2>&1
call "%~dp0run-windows.bat"
timeout /t 5 >nul
start "" http://localhost:8766
echo done task >> install.log
pause
exit /b 0

:fail
echo.
echo ================================================================
echo  Installing the packages failed ^(details in install.log^).
echo  - Check the internet connection ^(a VPN may help if all mirrors failed^).
echo  - Or install them by hand in this window, then run this file again:
echo      %PY% -m pip install -i https://mirror-pypi.runflare.com/simple -r requirements.txt
echo ================================================================
echo failed >> install.log
pause
exit /b 1
