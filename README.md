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

