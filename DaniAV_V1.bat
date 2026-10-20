@echo off
setlocal EnableExtensions
chcp 65001 >nul
title DaniAV

cd /d "%~dp0"

set "PYTHON_CMD="

where py >nul 2>&1
if %errorlevel%==0 set "PYTHON_CMD=py"

if not defined PYTHON_CMD (
    where python >nul 2>&1
    if %errorlevel%==0 set "PYTHON_CMD=python"
)

if not defined PYTHON_CMD (
    echo Python was not found.
    echo Install Python 3.9 or newer from python.org and tick "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import psutil" >nul 2>&1
if %errorlevel% neq 0 goto :install
%PYTHON_CMD% -c "import pypresence" >nul 2>&1
if %errorlevel% neq 0 goto :install
goto :run

:install
echo Installing requirements...
%PYTHON_CMD% -m pip --version >nul 2>&1
if %errorlevel% neq 0 %PYTHON_CMD% -m ensurepip --upgrade
%PYTHON_CMD% -m pip install --disable-pip-version-check -r "requirements.txt"
if %errorlevel% neq 0 (
    echo.
    echo Requirements could not be installed. Check your internet connection.
    pause
    exit /b 1
)

:run
%PYTHON_CMD% "DaniAV_V1.py" %*
set "EXIT_CODE=%errorlevel%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo DaniAV exited with code %EXIT_CODE%.
    pause
)
exit /b %EXIT_CODE%
