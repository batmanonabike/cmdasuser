@echo off
setlocal enableextensions

rem ============================================================
rem  Logon launcher - goes in the Startup folder.
rem
rem  This runs in the USER context at logon (the Startup folder
rem  cannot elevate). It drives CommandClient, which connects to
rem  the CommandServer service running as SYSTEM, so the command
rem  is executed as SYSTEM by the server - NOT by this script.
rem
rem  Prerequisites:
rem    - CommandServer service installed and running as SYSTEM
rem      (Automatic start, listening on 127.0.0.1:54000).
rem    - Machine-level env vars set (see docs/logon-task-setup.md).
rem
rem  CmdAsUser.exe is deliberately NOT used here: its "System"
rem  path reuses its own process token, so it only yields SYSTEM
rem  when already running as SYSTEM - which the Startup folder is
rem  not.
rem ============================================================

rem This launcher runs in the USER context, so %USERPROFILE% resolves to your
rem profile here and is safe to use as a fallback (unlike in logon-task.cmd,
rem which runs as SYSTEM). The machine-level vars, if set, take precedence.
if not defined CMDASUSER_HOME set "CMDASUSER_HOME=%USERPROFILE%\CmdAsUser"
if not defined CMDASUSER_BIN  set "CMDASUSER_BIN=%USERPROFILE%\source\repos\cmdasuser_02\x64\Release"

rem Feed the command(s) to CommandClient on stdin, then exit.
rem The server (SYSTEM) runs each line; cmd /c launches the .cmd task.
(
    echo cmd /c "%CMDASUSER_HOME%\logon-task.cmd"
    echo exit
) | "%CMDASUSER_BIN%\CommandClient.exe"

endlocal
