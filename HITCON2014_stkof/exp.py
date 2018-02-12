#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"

io = process("./stkof") if sys.argv[1] == "l" else \
        remote("127.0.0.1", 9999)


