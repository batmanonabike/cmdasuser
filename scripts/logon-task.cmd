@echo off
setlocal enableextensions

rem ============================================================
rem  CmdAsUser logon task (runs as SYSTEM)
rem
rem  Paths come from MACHINE-LEVEL environment variables so they
rem  resolve correctly under the SYSTEM account. If they are not
rem  set, we fall back to absolute defaults (edit to suit).
rem
rem  NOTE: do NOT rely on %USERPROFILE% / %TEMP% / %APPDATA% here
rem  - under SYSTEM they point at the SYSTEM profile, not a user.
rem
rem  See docs/logon-task-setup.md for setup instructions.
rem ============================================================

if not defined CMDASUSER_HOME set "CMDASUSER_HOME=C:\Users\Martyn.Brown\CmdAsUser"
if not defined CMDASUSER_LOG  set "CMDASUSER_LOG=%CMDASUSER_HOME%\logon-task.log"
if not defined CMDASUSER_PS   set "CMDASUSER_PS=%CMDASUSER_HOME%\startup.ps1"

rem First write uses > to recreate the log each run; all later writes append.
>"%CMDASUSER_LOG%"  echo ==========================================================
>>"%CMDASUSER_LOG%" echo [%DATE% %TIME%] task started
>>"%CMDASUSER_LOG%" echo HOME=%CMDASUSER_HOME%
>>"%CMDASUSER_LOG%" echo running as:
whoami            >>"%CMDASUSER_LOG%" 2>&1
whoami /user      >>"%CMDASUSER_LOG%" 2>&1

rem --- Optional: look for a PowerShell script and run it if present ---
if exist "%CMDASUSER_PS%" (
    >>"%CMDASUSER_LOG%" echo [%DATE% %TIME%] found PS script, executing: %CMDASUSER_PS%
    powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CMDASUSER_PS%" >>"%CMDASUSER_LOG%" 2>&1
    >>"%CMDASUSER_LOG%" echo [%DATE% %TIME%] PS exit code: %ERRORLEVEL%
) else (
    >>"%CMDASUSER_LOG%" echo [%DATE% %TIME%] no PS script at %CMDASUSER_PS% - skipping
)

>>"%CMDASUSER_LOG%" echo [%DATE% %TIME%] task finished
>>"%CMDASUSER_LOG%" echo.

endlocal
