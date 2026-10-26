#include <cstdio>
#include <iostream>
#include <vector>
#include "Utils.h"
#include "Exceptions.h"
#include "CommandServer.h"
#include "CommandMessage.h"
#include "CommandResponse.h"

using asio::ip::tcp;
using namespace CommandLib;

const std::string CommandServer::marker_ = "@REM MartWasHere";

CommandServer::CommandServer(tcp::socket&& socket) : socket_(std::move(socket)) {
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    /// Create pipes for the child process's STDIN and STDOUT
    if (!CreatePipe(stdInRead_.get_pointer(), stdInWrite_.get_pointer(), &saAttr, 0) ||
        !SetHandleInformation(stdInWrite_, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(stdOutRead_.get_pointer(), stdOutWrite_.get_pointer(), &saAttr, 0) ||
        !SetHandleInformation(stdOutRead_, HANDLE_FLAG_INHERIT, 0)) {
        throw std::runtime_error("Failed to create pipes");
    }

    STARTUPINFO startupInfo = { sizeof(STARTUPINFO) };
    startupInfo.hStdInput = stdInRead_;
    startupInfo.hStdError = stdOutWrite_;
    startupInfo.hStdOutput = stdOutWrite_;
    startupInfo.dwFlags |= STARTF_USESTDHANDLES;

    std::string cmd = "cmd.exe";
    std::vector<TCHAR> command_line;
    command_line.assign(cmd.begin(), cmd.end());
    command_line.push_back('\0'); // Add null terminator

    PROCESS_INFORMATION procInfo;
    if (!CreateProcess(NULL, &command_line[0], NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &procInfo)) {
        throw std::runtime_error("Failed to create process");
    }

    threadHandle_.reset(procInfo.hThread);
    processHandle_.reset(procInfo.hProcess);
}

void CommandServer::handle_client() {

    process_command(marker_); // Find the end of cmd output.

    try
    {
		std::string response = "Welcome to Marty's command server. Type 'exit' to quit.\n";
		response += "Current user: " + GetCurrentUserName() + "\n";
		response += "Current SID: " + GetCurrentSid() + "\n\n";
            
        response += read_stdout_response();
        send_response(response);

        while (true) {
            auto request = CommandMessage::try_receive(socket_);

            process_command(request.get_payload());
            process_command(marker_);

            auto response = read_stdout_response();
            send_response(response);
        }
    }
    catch (EndOfFileException&) {
        std::cout << "Connection closed by client" << std::endl;
    }
}

void CommandServer::send_response(const std::string & response)
{
    std::cout << "Server says: [" << response << "]" << std::endl;
    std::cout << "Server sends: " << response.size() << " bytes" <<std::endl;

    CommandMessage commandMessage{ response, "str2" };
    commandMessage.send(socket_);
}

void CommandServer::process_command(const std::string & command)
{
    std::cout << "Processing command: " << command << std::endl;
	std::string commandLine = command + "\n"; // signal cmd.exe to process it

    // Write the command to the cmd.exe process's STDIN
    DWORD written;
    if (!WriteFile(stdInWrite_, commandLine.c_str(), static_cast<DWORD>(commandLine.size()), &written, NULL)) {
        throw std::runtime_error("Failed to write to child process");
    }
}

std::string CommandServer::read_stdout_response() {
    DWORD read;
    std::string stdOutResponse;
    std::vector<char> output_buffer(1024 * 10);

    while (true) {
        if (!ReadFile(stdOutRead_, output_buffer.data(), static_cast<DWORD>(output_buffer.size()), &read, NULL) || read == 0) {
            throw std::runtime_error("Failed to read stdout pipe");
        }
        
        stdOutResponse.append(output_buffer.data(), read);
        if (stdOutResponse.find(marker_) != std::string::npos) {
            break;
        }
    }

	// Discard the marker   
    size_t marker_pos = stdOutResponse.find(marker_);
    if (marker_pos != std::string::npos) {
        stdOutResponse.resize(marker_pos);
    }

    return stdOutResponse;
}
