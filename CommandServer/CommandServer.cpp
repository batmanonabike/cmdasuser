#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <array>
#include <memory>
#include <cstdio>
#include <utility>
#include <optional>
#include <asio.hpp>
#include <CommandLib.h>
#include <tchar.h>
#include <windows.h> // wsock2.h is included in CommandLib.h

using asio::ip::tcp;
using namespace CommandLib;

void handle_client(tcp::socket && socket) {
    try {
        CommandServer server(std::move(socket));
        server.handle_client();
    }
    catch (std::exception& e) {
        std::cerr << "Exception in thread: " << e.what() << std::endl;
    }
}

int main() {
    // Run as a background daemon: hide our console window. Nothing depends on
    // it - the only thing it shows is diagnostic std::cout; the real work goes
    // over the socket and the child cmd.exe's redirected pipes. We are launched
    // via "CmdAsUser System . /c CommandServer.exe" (CREATE_NEW_CONSOLE), so a
    // console exists; hiding it here keeps no window on screen at logon.
    if (HWND hwndConsole = ::GetConsoleWindow()) {
        ::ShowWindow(hwndConsole, SW_HIDE);
    }

    try {
        asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 54000));

        std::cout << "Server is listening on port 54000..." << std::endl;

        while (true) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            std::thread(handle_client, std::move(socket)).detach();
        }
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
