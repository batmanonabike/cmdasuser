# Known Issues — logon SYSTEM task via the McbCmdAsUser service

Status: **open / unresolved**. This file records the problems seen after reworking `CmdAsUser`
into a persistent-service model, plus the diagnostic information gathered, so they can be
investigated later. It deliberately does **not** attempt fixes.

Captured: 2026-10-26.

## Context — what changed

`CmdAsUser` was extended so the SYSTEM privilege comes from a **persistent auto-start service**
instead of a throwaway one:

- New `CmdAsUser /install` (elevated): deploys the three binaries into System32/SysWOW64 and
  registers + starts an auto-start LocalSystem service named **`McbCmdAsUser`**.
- New `CmdAsUser /uninstall` (elevated): stops and removes it.
- Normal `CmdAsUser System . /c <cmd>`: if the service is running, hands the request to it over
  the shared-memory IPC (`McbExecuteViaRunningService`) — **no admin needed**; otherwise falls back
  to the original transient-service path (`McbInvokeService`).
- The logon launcher ([scripts/logon-startup-launcher.cmd](scripts/logon-startup-launcher.cmd))
  calls `CmdAsUser System . /c CommandServer.exe` then pipes the task into `CommandClient`.
- `CommandServer` gained `ShowWindow(GetConsoleWindow(), SW_HIDE)` at startup.

Relevant source: [CmdAsUser/McbCmdAsUser.cpp](CmdAsUser/McbCmdAsUser.cpp),
[CommandServer/CommandServer.cpp](CommandServer/CommandServer.cpp),
[CommandLib/CommandServer.cpp](CommandLib/CommandServer.cpp).

## Symptoms (user-reported, after re-login)

1. **`CommandServer` starts after re-login but the startup scripts do not execute** — the logon
   task (`logon-task.cmd` → `startup.ps1`) does not run.
2. **No new log is generated** — `C:\ProgramData\CmdAsUser\logon-task.log` is not refreshed.
3. **The `CommandServer` console (DOS) window STILL appears**, despite the `ShowWindow(SW_HIDE)`
   change being present in the deployed binary.
4. **Calling `CommandClient` now hangs** (did not before).

## Diagnostic snapshot

Collected 2026-10-26, *before* the user ran `/uninstall` and manually killed `CommandServer.exe`
(so the live process state below is now torn down — re-gather on next repro).

### Deployed binaries match the repo build (not stale)

| File | System32 size / mtime | repo `x64\Release` size / mtime |
|------|-----------------------|---------------------------------|
| CmdAsUser.exe     | 1300992 / 2026-10-26 08:06:42 | 1300992 / 2026-10-26 08:06:42 |
| CommandServer.exe | 100352  / 2026-10-26 08:06:56 | 100352  / 2026-10-26 08:06:56 |
| CommandClient.exe | 87552   / 2026-10-26 08:06:55 | 87552   / 2026-10-26 08:06:55 |

So the running `CommandServer.exe` **does** contain the `ShowWindow(SW_HIDE)` change, and the
binaries are the new (08:06) service-model build — not an older copy.

### Processes / port (first query, before teardown)

- `CommandServer.exe` **PID 22588, SessionId 0**, owner unreadable (`\`) = running as SYSTEM.
- Port **54000** `Listen` owned by **PID 27980** — a *different* PID from the session-0 server.
  → strong hint that **two `CommandServer` instances** existed, and the one actually holding the
  socket (27980) was not the session-0 one (22588). PID 27980's details could not be read before
  it went away.

### Service

- `McbCmdAsUser` service: existed during the failure, now **removed** (user ran `/uninstall`;
  `sc query McbCmdAsUser` → 1060 "service does not exist").

### Environment (machine-level)

```
CMDASUSER_HOME = C:\ProgramData\CmdAsUser
CMDASUSER_LOG  = C:\ProgramData\CmdAsUser\logon-task.log
CMDASUSER_PS   = C:\ProgramData\CmdAsUser\startup.ps1
CMDASUSER_BIN  = C:\WINDOWS\System32
```

### Install dir `C:\ProgramData\CmdAsUser`

```
logon-task.cmd   1803 bytes  2026-10-26 04:53:37
startup.ps1      1470 bytes  2026-10-26 05:06:45
logon-task.log    650 bytes  2026-10-26 07:11:05   <-- STALE (see below)
```

### The log shows a PAST SUCCESS at 07:11, then nothing

`logon-task.log` contents show one **successful** end-to-end run:

```
[26/10/2026  7:11:04.47] task started
running as: nt authority\system
[26/10/2026  7:11:04.78] found PS script, executing: ...\startup.ps1
[2026-10-26T07:11:05] DisableCAD set to 1 (Ctrl+Alt+Del not required)
[26/10/2026  7:11:04.78] PS exit code: 0
[26/10/2026  7:11:05.53] task finished
```

Key timing: the successful run was at **07:11**, but the current deployed binaries are timestamped
**08:06** — i.e. the 07:11 success used the *previous* binaries. After the 08:06 (service-model)
build was deployed and the machine re-logged-in, the task stopped running and the log was never
refreshed. **This points the regression at the 08:06 service-model changes.**

## Leads to investigate later (not yet confirmed)

### A. CommandClient hangs → task never runs → log stale (issues 1, 2, 4 are likely one bug)

The server's request handshake loops until it sees a marker string in the child `cmd.exe` output:

- marker `"@REM MartWasHere"` — [CommandLib/CommandServer.cpp:13](CommandLib/CommandServer.cpp#L13)
- `handle_client()` sends the marker then reads until it appears —
  [CommandLib/CommandServer.cpp:46](CommandLib/CommandServer.cpp#L46)
- `read_stdout_response()` loops on `ReadFile` **until the marker is found** (no timeout) —
  [CommandLib/CommandServer.cpp:95](CommandLib/CommandServer.cpp#L95)

Hypothesis: when `CommandServer` runs under SYSTEM in **session 0** (spawned by the service), the
child `cmd.exe`'s echo/prompt behaviour may differ enough that the marker never appears in stdout,
so `read_stdout_response` never returns → server never replies → `CommandClient` blocks forever.
The 07:11 success predates session-0 execution, which fits.

To gather next time (while reproduced):
- Session ID of the `CommandServer` that owns port 54000 (`Get-NetTCPConnection -LocalPort 54000`
  → owning PID → `Get-CimInstance Win32_Process -Filter ProcessId=<pid>` for SessionId/CommandLine).
- Whether a child `cmd.exe` is spawned under that server and what it emits (e.g. attach a debugger,
  or temporarily log `read_stdout_response` output / the raw bytes it is scanning).
- Confirm whether a bare `CommandClient` against a **session-1** (interactive) `CommandServer` still
  works, vs a **session-0** one — to confirm the session-0 theory.

### B. Two CommandServer instances / port ownership

The session-0 server (22588) was **not** the port owner (27980). Possible causes to check:
- The launcher's `tasklist` guard ([logon-startup-launcher.cmd:37](scripts/logon-startup-launcher.cmd#L37))
  only checks image name, not session/health — a second server can be launched while a stale one
  lingers, and whichever bound 54000 first keeps it.
- `CmdAsUser` may have taken the **transient fallback** (`McbInvokeService`) at logon if the
  service was not yet "running" at that instant, spawning an extra server. That path still uses
  `SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS`
  ([McbCmdAsUser.cpp](CmdAsUser/McbCmdAsUser.cpp) `McbInvokeService`) — see lead C.

To gather next time: count of `CommandServer.exe` processes, their SessionIds, start times, and
which one holds 54000.

### C. Window still appears (issue 3)

The deployed `CommandServer.exe` has `ShowWindow(SW_HIDE)`, and a session-0 process has no desktop,
so the visible window implies a `CommandServer` running in the **interactive session (1)**, not
session 0. Candidate explanations to check:
- The transient fallback service is created with `SERVICE_INTERACTIVE_PROCESS`, which can surface a
  process on the user desktop — producing a visible window and a session-1 server.
- Timing race: the auto-start `McbCmdAsUser` service may not be `RUNNING` at the moment the Startup
  launcher fires, so `CmdAsUser` falls back to transient instead of IPC.

To gather next time: at the moment the window is visible, record `sc query McbCmdAsUser` state and
the SessionId of the windowed `CommandServer`.

## Repro steps

1. Build x64 Release (whole solution).
2. Elevated: `CmdAsUser /install` (deploys binaries, installs + starts `McbCmdAsUser`).
3. Ensure the Startup shortcut to `logon-startup-launcher.cmd` is present.
4. Log off and back on.
5. Observe: `CommandServer` window appears; `logon-task.log` not refreshed; running
   `CommandClient` by hand hangs.

## Open questions

- Did the 07:11 success use the **old transient/interactive** model (session 1) and does the task
  only work when the server is session 1? If so, session 0 execution is the regression.
- Is `read_stdout_response`'s unbounded marker wait the actual hang, or does the client block
  earlier (e.g. connecting to a half-dead PID 27980 server)?
- Why are there two server instances — launcher guard, fallback path, or leftover process?

## Key files

- [CmdAsUser/McbCmdAsUser.cpp](CmdAsUser/McbCmdAsUser.cpp) — `/install`, `/uninstall`,
  `McbExecuteViaRunningService`, `McbInvokeService` (transient fallback), `McbInstallService`.
- [CommandServer/CommandServer.cpp](CommandServer/CommandServer.cpp) — accept loop + `ShowWindow`.
- [CommandLib/CommandServer.cpp](CommandLib/CommandServer.cpp) — client handshake / marker wait.
- [scripts/logon-startup-launcher.cmd](scripts/logon-startup-launcher.cmd) — logon launcher.
- [scripts/install-logon-task.ps1](scripts/install-logon-task.ps1) — installer (runs `/install`).
- [docs/logon-task-setup.md](docs/logon-task-setup.md) — design write-up.
