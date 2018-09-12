#include <stdio.h>

int main()
{
	char buf[0x10];
	gets(buf);
	puts(buf);
	return 0;
}
