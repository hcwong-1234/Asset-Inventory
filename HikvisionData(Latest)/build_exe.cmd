@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_exe.ps1"
if errorlevel 1 (
    echo.
    echo Build failed. Review the error messages above.
    pause
    exit /b 1
)
