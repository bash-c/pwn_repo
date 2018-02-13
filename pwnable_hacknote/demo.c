/* gcc demo.c -o demo */
#include <stdio.h>
#include <stdlib.h>

int main()
{
	char *p1 = (char *)malloc(0x10);
	printf("p1 -> %p\n", p1);
	free(p1);
	char *p2 = (char *)malloc(0x10);
	printf("p2 -> %p\n", p2);

	return 0;
}
