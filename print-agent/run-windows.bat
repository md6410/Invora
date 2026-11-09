@echo off
cd /d "%~dp0"
rem start the print station without a console window (pyw = windowed Python launcher)
where pyw >nul 2>&1 && (start "" pyw -3 agent.py & exit /b)
where pythonw >nul 2>&1 && (start "" pythonw agent.py & exit /b)
start "Invora Print Station" python agent.py
