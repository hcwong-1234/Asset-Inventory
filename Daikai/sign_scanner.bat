@echo off
title Daikai Scanner Code Signing
color 0A

set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
set "CERT=C:\Daikai\Certificate\DaikaiCodeSigning.pfx"
set "EXE=C:\Daikai\scanner.exe"

echo.
echo ==========================================
echo       Daikai Scanner Code Signing
echo ==========================================
echo.

if not exist "%SIGNTOOL%" goto SIGNTOOL_MISSING
if not exist "%CERT%" goto CERT_MISSING
if not exist "%EXE%" goto EXE_MISSING

set "PASSWORD="
set /p "PASSWORD=Enter PFX password: "

if not defined PASSWORD goto PASSWORD_MISSING

echo.
echo Signing:
echo "%EXE%"
echo.

"%SIGNTOOL%" sign /fd SHA256 /f "%CERT%" /p "%PASSWORD%" "%EXE%"

if errorlevel 1 goto SIGNING_FAILED

echo.
echo ==========================================
echo          SIGNING SUCCESSFUL
echo ==========================================
echo.
echo Verifying signature...
echo.

"%SIGNTOOL%" verify /pa /v "%EXE%"

if errorlevel 1 goto VERIFY_FAILED

echo.
echo ==========================================
echo       SIGNATURE VERIFIED SUCCESSFULLY
echo ==========================================
echo.
echo Signed file:
echo "%EXE%"
echo.
pause
exit /b 0

:SIGNTOOL_MISSING
echo ERROR: SignTool was not found.
echo.
echo Expected location:
echo "%SIGNTOOL%"
goto END_ERROR

:CERT_MISSING
echo ERROR: The PFX certificate was not found.
echo.
echo Expected location:
echo "%CERT%"
goto END_ERROR

:EXE_MISSING
echo ERROR: scanner.exe was not found.
echo.
echo Expected location:
echo "%EXE%"
goto END_ERROR

:PASSWORD_MISSING
echo.
echo ERROR: No password was entered.
goto END_ERROR

:SIGNING_FAILED
echo.
echo ==========================================
echo             SIGNING FAILED
echo ==========================================
goto END_ERROR

:VERIFY_FAILED
echo.
echo ==========================================
echo        SIGNATURE VERIFICATION FAILED
echo ==========================================
goto END_ERROR

:END_ERROR
echo.
pause
exit /b 1