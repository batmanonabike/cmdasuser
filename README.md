# CmdAsUser Project

This project is a comprehensive suite of tools designed for running commands as a specified user, managing Windows services, and performing DLL injection. Here's a detailed breakdown of each component:

## CmdAsUser
- **Purpose**: A console application to run commands as a specified user.
- **Key Features**: 
  - Handles security attributes, parameters, and results.
  - Functions for adding privileges, creating processes as a user, and managing services.
  - Utility functions for parsing parameters, copying files, and displaying usage information.
- **Files**: 
  - `CmdAsUser.vcxproj`: Project file for Visual Studio.
  - `McbCmdAsUser.cpp`: Main source file.
  - `McbFormatError.hpp`, `McbService.hpp`, `McbSmartCleanup.hpp`, `McbStrTok.hpp`, `McbTracing.hpp`, `NullSecurityAttributes.h`, `mcbaccesscontrol2.hpp`: Header files for various utilities.

## StopService
- **Purpose**: A tool to stop, enable, or disable Windows services.
- **Key Features**: 
  - Functions to manage service states.
  - Logging capabilities and privilege checks.
- **Files**: 
  - `StopService.cpp`: Main source file.
  - `StopService.vcxproj`: Project file for Visual Studio.

## CommandServer
- **Purpose**: A TCP server for handling client commands.
- **Key Features**: 
  - Manages a TCP socket and creates pipes for a child process (cmd.exe).
  - Handles client commands by processing them through the child process and sending back responses.
- **Files**: 
  - `CommandServer.cpp`: Main source file.
  - `CommandServer.vcxproj`: Project file for Visual Studio.

## CommandClient
- **Purpose**: A client application for sending commands to the server.
- **Key Features**: 
  - Sets up a TCP connection to localhost:54000.
  - Enters a loop to read server responses, display them, accept user commands, and send them back to the server until 'exit' is entered.
- **Files**: 
  - `CommandClient.cpp`: Main source file.
  - `CommandClient.vcxproj`: Project file for Visual Studio.

## CommandLib
- **Purpose**: A static library with classes for command processing, networking, and utility functions.
- **Key Features**: 
  - Classes for command processing, networking, and utility functions.
  - Includes `CommandClient`, `CommandServer`, `CommandMessage`, `CommandResponse`, `HandleGuard`, `Exceptions`, `Utils`, and `VirtualMemoryGuard`.
- **Files**: 
  - `CommandLib.vcxproj`: Project file for Visual Studio.
  - Various header and source files for each class.

## ConfigServiceUser
- **Purpose**: A tool for managing the 'Logon as a service' right.
- **Key Features**: 
  - Functions to add, remove, list, and clean up unmappable accounts for the 'Logon as a service' right.
- **Files**: 
  - `ConfigServiceUser.cpp`: Main source file.
  - `ConfigServiceUser.vcxproj`: Project file for Visual Studio.

## CommandInjectee
- **Purpose**: A dynamic library for DLL injection.
- **Key Features**: 
  - Defines functions for logging and suspending threads.
  - DLL entry point that logs events and suspends threads on attachment.
- **Files**: 
  - `dllmain.cpp`: Main source file.
  - `CommandInjectee.vcxproj`: Project file for Visual Studio.

## CommandInjector
- **Purpose**: A tool for injecting DLLs into processes.
- **Key Features**: 
  - Uses Windows API calls for DLL injection.
  - Includes error handling and path resolution for the DLL.
- **Files**: 
  - `CommandInjector.cpp`: Main source file.
  - `CommandInjector.vcxproj`: Project file for Visual Studio.

## Additional Files
- **EnableRealTimeScan.reg**: Windows Registry entries for Sophos Endpoint Defense, enabling real-time scanning.

The project uses C++17 standard, Unicode character set, and is configured for Debug and Release builds on Win32 and x64 platforms. For more detailed information, refer to the individual project files and their documentation.