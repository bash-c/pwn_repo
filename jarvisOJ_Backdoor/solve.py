#!/usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import sha256
from libnum import n2s

key = 0x20 + 4
key ^= 0x6443
print key
key = hex(key)[2: ]

print "PCTF{%s}" % (sha256(key.decode('hex')[::-1]).hexdigest())
