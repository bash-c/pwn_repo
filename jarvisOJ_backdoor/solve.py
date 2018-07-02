#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from hashlib import sha256
from libnum import n2s

key = 0x20 + 4
key ^= 0x6443
key = hex(key)[2: ]

print "PCTF{%s}" % (sha256(key.decode('hex')[::-1]).hexdigest())
