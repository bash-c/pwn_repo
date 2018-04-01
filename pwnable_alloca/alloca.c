#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void callme(){
	system("/bin/sh");
}

void clear_newlines(){
	int c;
	do{
		c = getchar();
	}while (c != '\n' && c != EOF);
}

int g_canary;
int check_canary(int canary){
	int result = canary ^ g_canary;
	int canary_after = canary;
	int canary_before = g_canary;
	printf("canary before using buffer : %d\n", canary_before);
	printf("canary after using buffer : %d\n\n", canary_after);
	if(result != 0){
		printf("what the ....??? how did you messed this buffer????\n");
	}
	else{
		printf("I told you so. its trivially easy to prevent BOF :)\n");
		printf("therefore as you can see, it is easy to make secure software\n");
	}
	return result;
}

int size;
char* buffer;
int main(){

	printf("- BOF(buffer overflow) is very easy to prevent. here is how to.\n\n");
	sleep(1);
	printf("   1. allocate the buffer size only as you need it\n");
	printf("   2. know your buffer size and limit the input length\n\n");

	printf("- simple right?. let me show you.\n\n");
	sleep(1);

	printf("- whats the maximum length of your buffer?(byte) : ");
	scanf("%d", &size);
	clear_newlines();

        printf("- give me your random canary number to prove there is no BOF : ");
        scanf("%d", &g_canary);
        clear_newlines();

	printf("- ok lets allocate a buffer of length %d\n\n", size);
	sleep(1);

	buffer = alloca( size + 4 );	// 4 is for canary

	printf("- now, lets put canary at the end of the buffer and get your data\n");
	printf("- don't worry! fgets() securely limits your input after %d bytes :)\n", size);
	printf("- if canary is not changed, we can prove there is no BOF :)\n");
	printf("$ ");

	memcpy(buffer+size, &g_canary, 4);	// canary will detect overflow.
	fgets(buffer, size, stdin);		// there is no way you can exploit this.

	printf("\n");
	printf("- now lets check canary to see if there was overflow\n\n");

	check_canary( *((int*)(buffer+size)) );
	return 0;
}

