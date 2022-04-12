#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include <iostream>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET hServSock = socket(PF_INET, SOCK_STREAM, 0);
	SOCKADDR_IN servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(8888);
	bind(hServSock, (SOCKADDR*)&servAddr, sizeof(servAddr));
	listen(hServSock, 5);
	SOCKET hClntSock;
	SOCKADDR_IN clntAddr;
	int clntAddrSz = sizeof(clntAddr);
	hClntSock = accept(hServSock, (SOCKADDR*)&clntAddr, &clntAddrSz);
	std::cout << "连接成功：" << inet_ntoa(clntAddr.sin_addr) << std::endl;
	while (1)
	{
		char cmd[1024];
		std::cout << "> ";
		std::cin.getline(cmd, sizeof(cmd));
		int nSendBytes;
		nSendBytes = send(hClntSock, cmd, 1024, 0);
		if (nSendBytes == SOCKET_ERROR)
		{
			break;
		}
		int len = 0;
		recv(hClntSock, (char*)&len, sizeof(int), 0);
		if (len == 0) {
			continue;
		}
		std::string result;
		char buf[1024];
		int recvCount = 0;
		while ((recvCount = recv(hClntSock, buf, sizeof(buf), 0)))
		{
			result.append(buf, recvCount);
			len -= recvCount;
			if (len == 0) {
				break;
			}
		}
		std::cout << result << endl;
	}
	closesocket(hClntSock);
	closesocket(hServSock);
	WSACleanup();
	return 0;
}