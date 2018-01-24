#include <stdio.h>

void vuln()
{
	char s[5];
	scanf("%s", s);
}

void func()
{
	printf("I'm here!\n");
}

int main()
{
	vuln();
	return 0;
}
