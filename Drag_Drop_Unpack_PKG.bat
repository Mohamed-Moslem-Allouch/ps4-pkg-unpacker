@echo off
setlocal enabledelayedexpansion
title PS4 PKG Unpacker (Drag and Drop)
color 0B

echo =======================================================
echo          PS4 PKG DRAG AND DROP UNPACKER
echo =======================================================
echo.

:: Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found on your system PATH!
    echo Please install Python 3.10+ from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo [TIP] Drag and drop one or more .pkg files directly onto this file!
    echo.
    set /p "PKG_FILE=Or enter / paste the full path to a .pkg file: "
    if "!PKG_FILE!"=="" (
        echo [ERROR] No file provided.
        goto done
    )
    set "PKG_FILE=!PKG_FILE:"=!"
    python "%~dp0unpack_ps4_pkg.py" "!PKG_FILE!"
    goto done
)

python "%~dp0unpack_ps4_pkg.py" %*

:done
echo.
echo =======================================================
echo Press any key to close this window...
pause >nul
