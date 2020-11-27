#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

f = lambda x: 16 * (((x & 0x3039) + 30) / 0x10)

allrand = []
for i in xrange(0xffff):
    allrand.append(f(i))

for i in set(allrand):
    print "{:#x}\t{}\t{}".format(i, allrand.count(i), float(allrand.count(i)) / sum(set(allrand)))
