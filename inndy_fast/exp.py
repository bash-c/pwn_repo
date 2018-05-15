#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from numpy import int32
import time
import re
#  context.log_level = 'debug'

#  io = process("./fast")
io = remote("hackme.inndy.tw", 7707)

io.sendlineafter("the game.\n", "Yes I know")

ans = ""
res = ""
f = lambda x: int32(int(x))
for i in xrange(10000):
    n1, op, n2 = io.recvuntil("=", drop = True).strip().split(' ')
    #  print n1, op, n2
    io.recvline()

    if op == '+':
        #  print n1, op, n2
        ans = str(f(n1) + f(n2))
    if op == '-':
        ans = str(f(n1) - f(n2))
    if op == '*':
        ans = str(f(n1) * f(n2))
    if op == '/':
        ans = str(int(float(n1) / int(n2)))

    res += (ans + " ")

#  print res
io.sendline(res)
io.interactive()
io.close()


