#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>


using namespace std;

int main()
{
    struct sockaddr_in serv_addr;
    int sock=0, conn=0;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8888);
    bind(sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
    listen(sock, 5);
    conn = accept(sock, (struct  sockaddr*)NULL, NULL);
    cout << "连接成功：" << std::endl;
	while (1)
	{
		char cmd[1024];
		cout << "> ";
		cin.getline(cmd, sizeof(cmd));
		int nSendBytes;
		nSendBytes = send(conn, cmd, 1024, 0);
		if (nSendBytes == -1)
		{
			break;
		}
		int len = 0;
		recv(conn, (char*)&len, sizeof(int), 0);
		if (len == 0) {
			continue;
		}
		string result;
		char buf[1024];
		int recvCount = 0;
		while ((recvCount = recv(conn, buf, sizeof(buf), 0)))
		{
			result.append(buf, recvCount);
			len -= recvCount;
			if (len == 0) {
				break;
			}
		}
		cout << result << endl;
	}
}