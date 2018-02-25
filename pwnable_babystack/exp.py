#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./babystack")
    elf = ELF("./babystack")
    #  libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("chall.pwnable.tw", 10205)
    elf = ELF("./babystack")
    libc = ELF("./libc_64.so.6")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)



