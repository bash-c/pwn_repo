#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pdb
with open("./libc.gadgets") as f:
    base = 0x5555e000
    whitelist = range(0x20, 0x80)
    g = f.readline()
    while g:
        #  print s
        g = f.readline()
        try:
            addr = int(g.split(":")[0], 16) + base
            asm = g.split(":")[1]
            #  print hex(addr), asm
            #  pdb.set_trace()
            byte = [int(hex(addr)[2: ][2 * i: 2 * i + 2], 16) for i in xrange(4)]
            #  print byte
            #  for i in byte:
                #  print hex(i),
            #  print "============="
            #  pdb.set_trace()
            if set(byte) < set(whitelist):
                print "{:#x}: {}".strip().format(addr, asm)
        except:
            continue
