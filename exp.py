#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import time
import re
#  context.log_level = 'debug'

io = process("./fast")
#  io = remote("hackme.inndy.tw", 7707)

io.sendlineafter("the game.\n", "Yes I know")

cnt = 0
last = '\n'

while cnt <= 10000:
    #  time.sleep(1)
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
    for exp in exps:
        #  print exp
        io.send(str(eval(exp)))

print io.recv()
io.close()



