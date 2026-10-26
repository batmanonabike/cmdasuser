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

### How the SYSTEM privilege is obtained

`CmdAsUser` can reach SYSTEM two ways:

- **Transient service (needs admin).** With no persistent service present, `CmdAsUser System . /c ...`
  opens the SCM for **write**, registers a throwaway service from a temp copy of itself, starts it as
  LocalSystem, hands it the request over shared memory, then stops and deletes it. Opening the SCM for
  write **requires administrator rights**, so from the non-elevated Startup folder this path fails with
  `Open SCM failed. Access is denied` (error 5).
- **Persistent service over IPC (no admin).** `CmdAsUser /install` (run once, elevated) registers a
  permanent **auto-start LocalSystem** service named `McbCmdAsUser`. Because it is always running as
  SYSTEM, a later `CmdAsUser System . /c ...` simply hands the request to it over the shared-memory IPC,
  whose kernel objects have a null DACL - so **a non-elevated caller can reach them**. No SCM access, no
  admin. This is what lets the logon launcher drive it.

So the **install is elevated** (it may touch the SCM); the **logon launcher is not** (it only does IPC
to the already-running service).

### The chain

```
Startup (user)
  -> CmdAsUser System . /c CommandServer.exe     (IPC to McbCmdAsUser service, SYSTEM)
        -> service spawns CommandServer as SYSTEM (session 0, no window)
  -> CommandClient  ->  CommandServer (SYSTEM)  ->  logon-task.cmd
```

`CommandClient` reads commands from stdin, so the launcher pipes them in.

### Starting the server

Before piping to `CommandClient`, the launcher ensures `CommandServer` is up:

```
tasklist /fi "imagename eq CommandServer.exe" | find /i "CommandServer.exe" >nul
if errorlevel 1 (
    "%CMDASUSER_BIN%\CmdAsUser.exe" System . /c CommandServer.exe
    >nul ping -n 3 127.0.0.1
)
```

`CommandServer.exe` lives in `System32` (on the PATH, deployed by `/install`). The `McbCmdAsUser`
service spawns it as SYSTEM in **session 0**, so there is **no visible window**. The short `ping` pause
gives the server time to bind `127.0.0.1:54000` before the client connects; without it `CommandClient`
can report `connect: No connection could be made because the target machine actively refused it`. The
`tasklist` guard avoids launching a second instance that would just fail to bind the port and exit.

> Because `CommandServer` runs in session 0 it survives logoff, and the `McbCmdAsUser` service is
> auto-start, so after a reboot it is back as SYSTEM before you log on - ready for the launcher.

### Prerequisites

- **Use the x64 builds throughout** (service, `CommandClient`, `CmdAsUser`). This project assumes 64-bit.
  A 32-bit process in the chain would hit WOW64 file-system redirection - references to
  `C:\Windows\System32` silently become `C:\Windows\SysWOW64`, and `powershell.exe` would resolve to the
  32-bit PowerShell. With x64 there is no redirection and these resolve correctly. (If you ever must run
  a 32-bit build, reach the real System32 via `%windir%\Sysnative`.)
- `CmdAsUser /install` has been run once, **elevated** (the installer does this in Step 1). It stops any
  running instance, deploys `CmdAsUser.exe`, `CommandClient.exe`, `CommandServer.exe` into
  `System32`/`SysWOW64` (putting them on the PATH), and installs + starts the `McbCmdAsUser` SYSTEM
  service. To remove it later: `CmdAsUser /uninstall` (elevated).
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

- The SYSTEM context comes from the `McbCmdAsUser` service account, not from the logon session - exactly
  the separation the project is built around.
- The logon launcher needs **no** elevation or Task Scheduler: it reaches the already-running SYSTEM
  service over IPC. Only the one-time `CmdAsUser /install` needs admin.
- `CommandServer` runs in session 0 (no desktop), so it never shows a window regardless of the
  `ShowWindow(SW_HIDE)` guard in `CommandServer.cpp`.
