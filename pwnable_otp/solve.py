#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import subprocess

io = process(["/home/otp/otp", ""], stderr = subprocess.STDOUT)
io.interactive()
