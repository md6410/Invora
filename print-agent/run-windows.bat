@echo off
cd /d "%~dp0"
where pythonw >nul 2>&1 && (start "" pythonw agent.py) || (start "Invora Print" python agent.py)
