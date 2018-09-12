#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main()
{
	getchar();

	puts("Open a file.");
	int fd = open("/dev/urandom", 0);
	getchar();

	printf("Close the file.\n");
	close(fd);
	getchar();

	return 0;
}
