@echo off
title PhishSim Server
cd /d "%~dp0"

echo ============================================
echo  Starting PhishSim Production Server...
echo ============================================
echo.

call ".venv\Scripts\activate.bat"
set PYTHONIOENCODING=utf-8
python run_production.py %*

echo.
echo Server stopped. Press any key to close...
pause >nul
