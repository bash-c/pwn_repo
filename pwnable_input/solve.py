#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
#  context.log_level = "debug"


#  print arg
with open("./stderr", "w") as f:
    f.write(b"\x00\x0a\x02\xff")

with open("\x0a", "w") as f:
    f.write(b"\x00\x00\x00\x00")

arg = ["/home/input2/input"] + ['a'] * 64 + ['\0'] + ['\x20\x0a\x0d'] + ['9999'] + ['a'] * 32 

stderr = open("./stderr", "rb")

env = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}

io = process(arg, stderr = stderr, env = env)

io.send("\x00\x0a\x00\xff")

p = remote("127.0.0.1", 9999)
p.send("\xde\xad\xbe\xef")
p.close()

io.interactive()
io.close()


