#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from sleep import *
import sys
context.log_level = "debug"

io = process("./note2") if sys.argv[1] == 'l' else remote("127.0.0.1", 9999)

def init():
    io.sendlineafter("name:\n", "M4x")
    io.sendlineafter("address:\n", "666")

def new(length, content):
    io.sendlineafter("--->>\n", "1")
    io.sendlineafter("128)\n", str(length))
    io.sendlineafter("content:\n", content)

def show(idx)
    io.sendlineafter("--->>\n", "2")
    io.sendlineafter("note:\n", str(idx))

def edit(idx, content, overwrite = True):
    io.sendlineafter("--->>\n", "3")
    io.sendlineafter("note:\n", str(idx))
    choice = 1 if overwrite else 2
    io.sendlineafter("]\n", str(choice))
    io.sendlineafter("content:\n", content)

def delete(idx):
    io.sendlineafter("--->>\n", "4")
    io.sendlineafter("note:\n", str(idx))
