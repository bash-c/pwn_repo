#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import pdb
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./note2") if sys.argv[1] == "l" else remote("127.0.0.1", 9999)
elf = ELF("./note2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def init():
    #  pdb.set_trace()
    io.sendlineafter("name:\n", "M4x")
    io.sendlineafter("address:\n", "0000")

def new(length, content):
    io.sendlineafter("--->>\n", "1")
    io.sendlineafter("128)\n", str(length))
    io.sendlineafter("content:\n", content)
    
def show(idx):
    io.sendlineafter("--->>\n", "2")
    io.sendlineafter("note:\n", str(idx))

def edit(idx, content, overwrite = True):
    io.sendlineafter("--->>\n", "3")
    io.sendlineafter("note:\n", str(idx))
    overwrite = 1 if overwrite else 2
    io.sendlineafter("]\n", str(overwrite))
    io.sendlineafter("Contents:", content)

def delete(idx):
    io.sendlineafter("--->>\n", "4")
    io.sendlineafter("note:\n", str(idx))
