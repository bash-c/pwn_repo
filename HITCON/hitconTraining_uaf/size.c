/* gcc size.c -m32 -o size */
#include <stdio.h>

int main()
{
	int *p1;
	printf("p1 -> %d\n", sizeof(p1));
	char *p2;
	printf("p2 -> %d\n", sizeof(p2));
	float *p3;
	printf("p3 -> %d\n", sizeof(p3));
	return 0;
}
