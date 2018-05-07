#include <stdio.h>

int main()
{
	char *buf;
	read(0, buf, -1);
	puts(buf);
	return 0;
}
