// gcc play_with_fd.c -o play_with_fd
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main()
{
	puts("Now stdout is on.");
	puts("And then we close stdout.");

	close(1);
	puts("dumb output because stdout is closed.");

	int fd = open("output.txt", O_RDWR | O_CREAT, 0777);
	puts("Since open() returns 1 and puts() triggers write(1,....), this message will be written to the file output.txt");
	close(fd); // don't forget to close(fd)!!!
	
	return 0;
}
