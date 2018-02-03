#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <regex.h>
#include <sys/socket.h>

int main()
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);//创建套接字
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;//使用IPV4地址
	serv_addr.sin_addr.s_addr = inet_addr("hackme.inndy.tw");
	serv_addr.sin_port = 7707;//端口
	connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

	char buf[400];
	read(sock, buf, sizeof(buf) - 1);

	printf("Received: %s\n", buf);

	close(sock);
	return 0;
}
