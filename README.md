# CmdAsUser

`CmdAsUser` is a Windows C++/Win32 systems-programming project that allows an administrator to
execute commands with extremely high Windows privileges, including the
`SeTcbPrivilege`-style "Act as part of the operating system" security context.

The project also provides a reverse shell: an interactive command prompt connected directly to a
process running with those elevated privileges. This allows commands to be entered remotely through
the client/server interface and executed inside the high-privilege Windows process.

The project demonstrates:

- Windows administrator and service-account configuration
- High-privilege Windows security contexts
- Process creation and control
- Interactive command execution
- Reverse-shell communication
- TCP client/server design
- Anonymous pipes for standard input, output and error
- Cross-process memory operations
- DLL injection
- Windows service integration
- C and C++ Win32 systems programming

The foundations of this code were written more than 20 years ago. The repository has since been
extended and experimented with over time, but some of the underlying implementation and design
decisions are from that earlier period.

This repository is an educational and technical demonstration of Windows internals, process
security and systems programming. It is not production-hardened security software and must not be
exposed to untrusted users or networks.

## How It Works

The project installs a Windows service configured to run under an account with the required
high-level operating-system privilege.

Once the service is running:

1. A client connects to the service using the project's IPC mechanism.
2. The client sends a command request to the service.
3. The service executes the command within its own privileged process context.
4. Standard output and standard error are redirected back through the IPC channel.
5. The client presents the response as an interactive command prompt.

This separates the interactive client from the privileged execution process. The client does not
need to hold the high-level privilege itself; the Windows service owns that privilege and performs
the command execution on the client's behalf.

The project explores more than one communication path, including local process communication and
the TCP-based client/server demonstration. The TCP path provides the reverse-shell-style interactive
experience, while the service path demonstrates how Windows service accounts, privileges and
inter-process communication can be combined.

## Example Usage

Once `CommandClient` is connected to the privileged service, commands typed at its prompt are
executed in the SYSTEM context and their output is returned over the IPC channel.

For example, a developer whose machine requires Ctrl+Alt+Del at the logon screen (set via Group
Policy) can disable that requirement by running the following from `CommandClient`:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 1 /f
```

Notes:

- This sets the `DisableCAD` policy value (equivalent to the *"Interactive logon: Do not require
  CTRL+ALT+DEL"* security option). It takes effect at the next lock/logon screen; no reboot is
  needed.
- Because the same value is managed by Group Policy, the next `gpupdate` or reboot will re-apply the
  domain setting and may revert this change. The durable fix is for IT to change it in the GPO / your
  OU; the command above is a local workaround until they do.
- Disabling the Secure Attention Sequence is a deliberate (minor) security tradeoff, which is why the
  policy exists. Only do this on a machine you are authorised to administer.

## Logon Task (run a script as SYSTEM at logon)

The repo includes a small framework for running a script in the SYSTEM context automatically at every
logon - for example, to apply the `DisableCAD` fix above on each sign-in.

### What it does

```
Logon (user context)  ->  logon-startup-launcher.cmd  ->  CommandClient
                               ->  CommandServer service (SYSTEM)  ->  logon-task.cmd  ->  startup.ps1
```

- The SYSTEM privilege comes from the **CommandServer service**, which already runs as SYSTEM. The
  Startup-folder launcher runs unelevated in the user context and simply drives `CommandClient`, which
  connects to the service; the service executes the work as SYSTEM.
- `logon-task.cmd` recreates a log each run, records the account it is running as, and - if a
  PowerShell script is present - executes it and captures its output.
- `startup.ps1` is the default payload. As shipped it disables the Ctrl+Alt+Del logon requirement
  (`DisableCAD`); edit it to do whatever SYSTEM-level work you need.

All paths are driven by machine-level environment variables (`CMDASUSER_HOME`, `CMDASUSER_LOG`,
`CMDASUSER_PS`, `CMDASUSER_BIN`) so they resolve correctly under SYSTEM and for every user. The scripts
live in [`scripts/`](scripts); the details are in [docs/logon-task-setup.md](docs/logon-task-setup.md).

### Setting it up

1. Build the x64 Release (the project assumes 64-bit throughout).
2. From an **elevated** prompt, run the installer:

   ```
   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-logon-task.ps1
   ```

   It invokes `CmdAsUser.exe` (which copies itself, `CommandClient.exe` and `CommandServer.exe` into
   System32/SysWOW64), copies `startup.ps1` and `logon-task.cmd` into the install location
   (`%ProgramData%\CmdAsUser` by default), and sets the `CMDASUSER_*` machine variables with `setx /M`.
   Any step that fails is reported and the script exits with a non-zero code.
3. Add the Startup-folder shortcut so it runs at logon (see
   [docs/logon-task-setup.md](docs/logon-task-setup.md) section 4), then log off and back on and check
   the log.

> The SYSTEM context depends on the CommandServer service being installed and running as SYSTEM
> (Automatic start). The installer configures the logon task, not the service itself.

## Security Warning

This project creates a deliberately powerful Windows execution mechanism.

An administrator can use it to launch or control a command process running with high-level
operating-system privileges. The reverse-shell component provides an interactive command prompt
directly into that privileged process.

In practical terms, this means that anyone who can access an insufficiently protected server could
potentially execute arbitrary commands with the server process's privileges. The tool must therefore
be treated as an administrative security demonstration and, effectively, as a remote-code-execution
mechanism.

For safe experimentation:

- Run it only on a machine you own or are explicitly authorised to administer.
- Use an isolated test environment.
- Bind communication to loopback unless remote access is specifically required.
- Restrict the TCP port with Windows Firewall.
- Do not expose the service to the public internet.
- Do not run it on production systems.
- Do not use it as a security boundary without substantial redesign and testing.
- Review every account and privilege change made by `ConfigServiceUser`.

## Historical Context

The foundations of the project were written over 20 years ago, when Windows systems programming
often required working directly with Win32 APIs, MSDN media and low-level operating-system
interfaces.

The repository reflects that history. It combines older code with later experiments and extensions
covering process creation, service accounts, privilege management, pipes, TCP communication,
reverse-shell behaviour and DLL injection.

It is therefore best understood as a long-running Windows systems-programming workbench and
demonstration rather than as a modern, production-ready application.

