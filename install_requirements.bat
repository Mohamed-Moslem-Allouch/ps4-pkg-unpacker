@echo off
title Install Requirements - PS4 PKG Unpacker
color 0A

echo =======================================================
echo     Installing Dependencies for PS4 PKG Unpacker
echo =======================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found on your system PATH!
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)

echo Running: python -m pip install -r "%~dp0requirements.txt"
python -m pip install -r "%~dp0requirements.txt"

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Dependencies installed successfully!
    echo You can now drag and drop .pkg files onto Drag_Drop_Unpack_PKG.bat
) else (
    echo.
    echo [ERROR] Failed to install dependencies. Check your internet connection.
)

echo.
pause
