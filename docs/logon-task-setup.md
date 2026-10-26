# Running a CmdAsUser Task on Logon

This describes how to run a script in the SYSTEM context automatically at Windows logon using
`CmdAsUser`, with all paths driven by environment variables and results written to a log.

> Run this only on a machine you own or are explicitly authorised to administer. The task executes
> with full SYSTEM privileges.

## 1. Why environment variables (and which kind)

`CmdAsUser System . /c ...` runs the command as **SYSTEM**. Under SYSTEM:

- `%USERPROFILE%`, `%APPDATA%`, `%TEMP%` resolve to the **SYSTEM** profile
  (`C:\Windows\System32\config\systemprofile`), **not** your user profile.
- **User**-level environment variables are not loaded.

So paths must come from **machine-level (System) environment variables**, which *are* visible to a
SYSTEM process. This project uses three:

| Variable          | Purpose                                             | Example                                  |
|-------------------|-----------------------------------------------------|------------------------------------------|
| `CMDASUSER_HOME`  | Base folder for the task and its files              | `C:\Users\Martyn.Brown\CmdAsUser`        |
| `CMDASUSER_LOG`   | Log file the task appends to                         | `%CMDASUSER_HOME%\logon-task.log`        |
| `CMDASUSER_PS`    | PowerShell script to run **if present**              | `%CMDASUSER_HOME%\startup.ps1`           |

The task script (`logon-task.cmd`) falls back to absolute defaults if these are not defined.

### Set the machine-level variables

Run once from an elevated prompt (the `/M` makes them machine-level):

```
setx /M CMDASUSER_HOME "%USERPROFILE%\CmdAsUser"
setx /M CMDASUSER_LOG  "%USERPROFILE%\CmdAsUser\logon-task.log"
setx /M CMDASUSER_PS   "%USERPROFILE%\CmdAsUser\startup.ps1"
```

Using `%USERPROFILE%` here avoids hardcoding your user name. **It expands at setup time, in your own
elevated session, and the resolved absolute path is stored** - e.g. `C:\Users\Martyn.Brown\CmdAsUser`.
That "expand once, frozen thereafter" behaviour is exactly what you want: the machine-level variable
ends up holding a concrete path that the SYSTEM task can read. Do **not** try to store a literal
`%USERPROFILE%` in a machine variable - at logon SYSTEM would expand it to the SYSTEM profile, not
yours.

Two things to note:

- `setx` always expands and stores literally; it does not keep a live reference.
- You cannot chain these in one batch - `setx /M CMDASUSER_LOG "%CMDASUSER_HOME%\..."` would fail on
  the second line because the just-set machine variable is not yet in the current process environment.
  That is why all three use `%USERPROFILE%`. (Alternatively: set `CMDASUSER_HOME`, open a new shell,
  then set the others.)

New values are picked up by processes started afterwards - a fresh logon is enough. Confirm from a new
shell with `echo %CMDASUSER_HOME%`.

## 2. The task script

The source of truth for both scripts lives in the repo under [`scripts/`](../scripts):
[`logon-task.cmd`](../scripts/logon-task.cmd) and [`startup.ps1`](../scripts/startup.ps1). Deploy
(copy) them into `CMDASUSER_HOME` for use; edit the repo copies, not the deployed ones.

`logon-task.cmd` (deployed to `CMDASUSER_HOME`):

- resolves its paths from the environment variables above,
- logs who it is running as (`whoami`, `whoami /user`) so you can confirm the SYSTEM context,
- if `CMDASUSER_PS` exists, runs it via
  `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CMDASUSER_PS%"` and logs
  the exit code,
- if it does not exist, logs that it was skipped.

`-ExecutionPolicy Bypass` is scoped to this single invocation (it does not change machine policy) and
lets an unsigned local script run. Only point `CMDASUSER_PS` at a script you control.

### Example `startup.ps1`

A minimal PowerShell script that writes to the same log and does its own work:

```powershell
$log = $env:CMDASUSER_LOG
if (-not $log) { $log = 'C:\Users\Martyn.Brown\CmdAsUser\logon-task.log' }

"[{0}] startup.ps1 running as {1}" -f (Get-Date), (whoami) | Out-File -Append $log

# ... your logon work here ...
```

Because `CmdAsUser` passes the SYSTEM environment through, `$env:CMDASUSER_LOG` is available inside
PowerShell too.

## 3. Test it manually first

Before wiring anything to logon, confirm the chain works. From the folder containing `CmdAsUser.exe`
(e.g. `x64\Release`):

```
CmdAsUser System . /c cmd.exe /c "%CMDASUSER_HOME%\logon-task.cmd"
```

`CreateProcessAsUser` does not run `.cmd` files directly, so the script is launched through
`cmd.exe /c`. Then inspect `CMDASUSER_LOG` - you should see the timestamps, `whoami` reporting
`nt authority\system`, and either the PowerShell run or the "skipped" line.

## 4. Run on logon via the Startup folder

### Why not call CmdAsUser directly from Startup

`CmdAsUser`'s `System` path reuses **its own process token**
([`OpenProcessToken(GetCurrentProcess())`](../CmdAsUser/McbCmdAsUser.cpp)) - it does not fetch a SYSTEM
token from elsewhere. So `CmdAsUser System . /c ...` only produces a SYSTEM process when `CmdAsUser.exe`
is **already** running as SYSTEM. The Startup folder runs in your **normal, unelevated user context**,
so calling `CmdAsUser` there would run as you (and `CreateProcessAsUser` would likely fail with
`ERROR_PRIVILEGE_NOT_HELD`) - not as SYSTEM.

### The route that works

The privilege lives in the **CommandServer service** (running as SYSTEM). The Startup entry simply
drives `CommandClient`, which connects to that service over `127.0.0.1:54000`; the server executes the
command as SYSTEM:

```
Startup folder (user)  ->  CommandClient  ->  CommandServer service (SYSTEM)  ->  logon-task.cmd
```

`CommandClient` reads commands from stdin, so the launcher pipes them in.

### Prerequisites

- **Use the x64 builds throughout** (service, `CommandClient`, `CmdAsUser`). This project assumes 64-bit.
  A 32-bit process in the chain would hit WOW64 file-system redirection - references to
  `C:\Windows\System32` silently become `C:\Windows\SysWOW64`, and `powershell.exe` would resolve to the
  32-bit PowerShell. With x64 there is no redirection and these resolve correctly. (If you ever must run
  a 32-bit build, reach the real System32 via `%windir%\Sysnative`.)
- `CommandServer` service installed and running as SYSTEM, **Automatic** start (so it is up at logon).
- Machine-level env vars set (section 1). Add one more for the binaries:
  ```
  setx /M CMDASUSER_BIN "%USERPROFILE%\source\repos\cmdasuser_02\x64\Release"
  ```

### Steps

1. Deploy [`scripts/logon-startup-launcher.cmd`](../scripts/logon-startup-launcher.cmd) somewhere stable
   (e.g. `CMDASUSER_HOME`). It feeds `cmd /c "%CMDASUSER_HOME%\logon-task.cmd"` then `exit` into
   `CommandClient`.
2. Open the per-user Startup folder: press `Win+R`, enter `shell:startup`.
   (Path: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.)
3. Create a **shortcut** in that folder pointing at the launcher, e.g. target:
   `%CMDASUSER_HOME%\logon-startup-launcher.cmd`. Set "Run: Minimized" on the shortcut to avoid a
   console flash if you like.
4. Log off and back on. Check `CMDASUSER_LOG` - it should be freshly recreated and show the task
   running as `nt authority\system`.

### Notes

- Because this goes through the service, the SYSTEM context comes from the service account, not from the
  logon session - exactly the separation the project is built around.
- If you would rather use the `CmdAsUser System . /c ...` form at logon, that requires a launcher that
  is itself SYSTEM - i.e. **Task Scheduler** with a trigger "At log on" and "Run whether user is logged
  on or not" under the SYSTEM account. That is an alternative to the Startup folder, not a companion to
  it.
