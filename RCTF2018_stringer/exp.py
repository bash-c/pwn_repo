#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./stringer"
libcPath = "./libc.so.6"
remoteAddr = "localhost"
remotePort = 9999

context.log_level = "debug"
context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
        context.log_level = "info"
    if libcPath:
        libc = ELF(libcPath)

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

def add(size, cont):
    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", str(size))
    io.sendafter(": ", cont)

def edit(idx, bidx):
    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", str(idx))
    io.sendlineafter(": ", str(bidx))

def delete(idx):
    io.sendlineafter(": ", "4")
    io.sendlineafter(": ", str(idx))


if __name__ == "__main__":
    
    io.interactive()
    io.close()


