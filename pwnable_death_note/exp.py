#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./death_note")
    elf = ELF("./death_note")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

else:
    io = remote("chall.pwnable.tw", 10201)
    elf = ELF("./death_note")
    #  libc = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def addName(idx, name):
    io.sendlineafter("choice :", "1")
    io.sendlineafter("Index :", str(idx))
    io.sendlineafter("Name :", name)

def showName(idx):
    io.sendlineafter("choice :", "2")
    io.sendlineafter("Index :", str(idx))

def delName(idx):
    io.sendlineafter("choice :", "3")
    io.sendlineafter("Index :", str(idx))

if __name__ == "__main__":






