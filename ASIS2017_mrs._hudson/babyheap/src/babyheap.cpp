#define _X86_
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <synchapi.h>
#include <windows.h>

char * g_sword[18] = { 0 };
bool g_inuse[18] = { 0 };
HANDLE g_heap = 0;

void read_n(char * s, int size)
{
	int idx = 0;
	char c = getchar();
	do
	{
		if (c == '\n')
		{
			break;
		}
		s[idx++] = c;
		c = getchar();
	} while (idx != size);
}

void error()
{
	puts("Something error");
	exit(0);
}


void scanf_wrapper(const char * fmt, int & value)
{
	if (scanf_s(fmt, &value) != 1)
	{
		error();
	}
	else
	{
		char c = getchar();
	}
}

void add()
{
	int size = -1;
	puts("\nNew weapon brings new power.");
	puts("Answer my questions so I can make a sword for you.\n");
	puts("How long is your sword?");
	scanf_wrapper("%d", size);

	if (size <= 0 || size > 0x100)
	{
		puts("Oh no, be realistic!");
	}

	char * sword = (char *)HeapAlloc(g_heap, HEAP_NO_SERIALIZE, size);

	if (sword)
	{
		for (int idx = 0; idx < 18; idx++)
		{
			if (!g_inuse[idx])
			{
				g_sword[idx] = sword;
				g_inuse[idx] = true;
				puts("Well done! Name it!");
				read_n(g_sword[idx], size);
				return;
			}
		}

		puts("You have carried so many swords, take easy!");
	}
	else
	{
		error();
	}
}

void destroy()
{
	int idx = -1;
	puts("\nLet the past be the past.\n");
	puts("Which sword do you want to destroy?");
	scanf_wrapper("%d", idx);

	if (idx < 0 || idx >= 18)
	{
		puts("no no no, be kind!");
		return;
	}

	if (g_inuse[idx])
	{
		bool retval = HeapFree(g_heap, HEAP_NO_SERIALIZE, g_sword[idx]);
		if (!retval)
		{
			error();
		}
		else
		{
			// g_sword[idx] = 0; // debug
			g_inuse[idx] = false;
			puts("Succeed!");
		}
	}
	else
	{
		puts("It seems that you don't own this sword.");
	}

}

void polish()
{
	int idx = -1;
	puts("\nA little change will make a difference.\n");
	puts("Which one will you polish?");
	scanf_wrapper("%d", idx);

	if (idx < 0 || idx >= 18)
	{
		puts("error");
		return;
	}

	if (g_inuse[idx])
	{
		int size = 0;
		puts("And what's the length this time?");
		scanf_wrapper("%d", size);
		puts("Then name it again : ");

		read_n(g_sword[idx], size); // heap overflow
	}
	else
	{
		puts("It seems that you don't own this sword.");
	}
}

void check()
{
	int idx = -1;
	puts("\nCherish what you've own.\n");
	puts("Which one will you check?");
	scanf_wrapper("%d", idx);

	if (idx < 0 || idx >= 18)
	{
		puts("no");
		return;
	}

	if (g_inuse[idx])
	{
		printf("Show : %s\n", g_sword[idx]);
	}
	else
	{
		puts("It seems that you don't own this sword.");
	}
}

void init()
{
	setvbuf(stdout, NULL, _IONBF, 0);
	
	g_heap = HeapCreate(HEAP_NO_SERIALIZE, 0x2000, 0x2000);
	puts("Welcome to my old-school menu-style babyheap.exe v1.0!");
	Sleep(1000);
	puts("I call it the Novice Village.");
	Sleep(1000);
	puts("Hope you learn some windows exploitation skills through this challenge :)");
	Sleep(1000);
	printf("And here is your Novice village gift : 0x%p\n", &read_n);
}

int menu()
{
	int choice = -1;
	puts("\nSo what do you want?");
	puts("1. Make a sword");
	puts("2. Destroy a sword");
	puts("3. Polish a sword");
	puts("4. Check a sword");
	puts("5. Weapon is equipped. I'm ready for new challenge!");
	puts("What's your choice?");
	scanf_wrapper("%d", choice);

	return choice;
}

int main()
{
	init();
	int choice = 0;
	bool bullet = 1;
	while (choice = menu(), choice != 5)
	{
		switch (choice)
		{
		case 1:
			add();
			break;
		case 2:
			destroy();
			break;
		case 3:
			polish();
			break;
		case 4:
			check();
			break;
		case 1337:
			puts("You find the hidden level!");
			if (bullet)
			{
				puts("Qualified!");
				puts("Forget awkward SWORDs, you will experience the power of GUNs!");
				puts("But only once in Novice Village.");
				puts("So what's your target?");
				int target = 0;
				scanf_wrapper("%d", target);
				char* p_target = (char *)target;
				*p_target = bullet;
				puts("Hit the target, awesome shoot!");
				bullet = 0;
			}
			else
			{
				puts("But you are not qualified this time...");
			}
			break;
		default:
			puts("invalid!");
			break;
		}
	}
}