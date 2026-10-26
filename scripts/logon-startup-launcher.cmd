@echo off
setlocal enableextensions

rem ============================================================
rem  Logon launcher - goes in the Startup folder.
rem
rem  This runs in the USER context at logon (the Startup folder
rem  cannot elevate). It:
rem    1. Asks CmdAsUser to ensure CommandServer is running as
rem       SYSTEM. The persistent McbCmdAsUser service (installed
rem       by install-logon-task.ps1) is already running as SYSTEM,
rem       so CmdAsUser reaches it over IPC and needs NO admin here
rem       - the service spawns CommandServer as SYSTEM in session 0
rem       (no visible window).
rem    2. Drives CommandClient, which connects to CommandServer
rem       over 127.0.0.1:54000; the server runs each command as
rem       SYSTEM - NOT this script.
rem
rem  Prerequisites:
rem    - "CmdAsUser /install" has been run once (elevated) to deploy
rem      the binaries into System32 and install + start the
rem      McbCmdAsUser SYSTEM service. See docs/logon-task-setup.md.
rem    - Machine-level env vars set (see docs/logon-task-setup.md).
rem ============================================================

rem This launcher runs in the USER context, so %USERPROFILE% resolves to your
rem profile here and is safe to use as a fallback (unlike in logon-task.cmd,
rem which runs as SYSTEM). The machine-level vars, if set, take precedence.
if not defined CMDASUSER_HOME set "CMDASUSER_HOME=%USERPROFILE%\CmdAsUser"
if not defined CMDASUSER_BIN  set "CMDASUSER_BIN=%USERPROFILE%\source\repos\cmdasuser_02\x64\Release"

rem Make sure the SYSTEM-side CommandServer is running before we connect.
rem The McbCmdAsUser service (SYSTEM) is already up, so this CmdAsUser call
rem reaches it over IPC WITHOUT needing admin; the service spawns CommandServer
rem as SYSTEM in session 0 (no window). The tasklist guard avoids launching a
rem second, port-blocked instance when one is already running.
tasklist /fi "imagename eq CommandServer.exe" | find /i "CommandServer.exe" >nul
if errorlevel 1 (
    "%CMDASUSER_BIN%\CmdAsUser.exe" System . /c CommandServer.exe
    rem Give the listener a moment to bind 127.0.0.1:54000 before connecting.
    >nul ping -n 3 127.0.0.1
)

rem Feed the command(s) to CommandClient on stdin, then exit.
rem The server (SYSTEM) runs each line; cmd /c launches the .cmd task.
(
    echo cmd /c "%CMDASUSER_HOME%\logon-task.cmd"
    echo exit
) | "%CMDASUSER_BIN%\CommandClient.exe"

endlocal
