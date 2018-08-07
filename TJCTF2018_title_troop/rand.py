#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

import ctypes

dll = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
dll.srand(0)

for i in xrange(8):
    print "{:#x}".format((dll.rand() & 0xff) % 10),
