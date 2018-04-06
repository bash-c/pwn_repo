#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = "M4x"

from pwn import *
#  from subprocess import Popen, PIPE
from math import ceil
from numpy import int32
import sys
import time
import re
#  context.log_level = 'debug'

if sys.argv[1] == "l":
    io = process("./fast")
else:
    io = remote("hackme.inndy.tw", 7707)

io.sendlineafter("the game.\n", "Yes I know")

cnt = 0
last = '\n'

while cnt <= 10000:
    #  time.sleep(0.01)
    success("%d exps calculated!" % cnt)
    try:
        text = last.strip() + io.recv(1000)
    except:
        text = last.strip() + io.recv()
    #  print text
    exps = re.split(r"\s?=\s?\?\n", text)
    #  print exps

    last = exps[-1]
    exps = exps[: -1]

    cnt += len(exps)
    #  result = [str(ctypes.c_int32(int(ceil(eval(i)))).value) + "\n" for i in exps]
    #  io.send(''.join(result))

    
    for exp in exps:
        #  exp = exp.split()
        n1, op, n2 = exp.split()
        exp = str(int32(n1)) + op + str(int32(n2))
        io.send(str(int32(ceil(eval(exp)))))

io.interactive()
io.close()
