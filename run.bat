@echo off
cd /d "%~dp0"
echo Starting PhishShift dashboard ...
where py >nul 2>nul
if %errorlevel%==0 (py -3 run.py %*) else (python run.py %*)
echo.
pause
