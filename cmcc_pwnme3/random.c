#include <stdio.h>
#include <stdlib.h>

int main()
{
	unsigned int v15 = 0x62626262;
	srand(v15);

	for(int i = 0; i <= 99; i++)
	{
		int v14 = rand();
		srand(v14);
		unsigned v13 = rand() % 0x1869Fu + 1;
		printf("%u, ", v13);
	}
}
